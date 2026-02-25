package io.jenkins.plugins.akeyless.credentials.provider.auth;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.time.Duration;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TimeZone;
import java.util.TreeMap;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Generates cloud identity tokens for AWS IAM, Azure AD, and GCP authentication
 * by calling cloud metadata services.
 */
public final class CloudIdProvider {

    private static final Logger LOG = Logger.getLogger(CloudIdProvider.class.getName());
    private static final Duration HTTP_TIMEOUT = Duration.ofSeconds(5);

    private CloudIdProvider() {}

    // ── AWS IAM ──────────────────────────────────────────────────────────

    public static String generateAwsCloudId() throws Exception {
        String accessKeyId = System.getenv("AWS_ACCESS_KEY_ID");
        String secretKey = System.getenv("AWS_SECRET_ACCESS_KEY");
        String sessionToken = System.getenv("AWS_SESSION_TOKEN");

        if (accessKeyId != null && secretKey != null) {
            LOG.log(Level.INFO, "AWS IAM cloud-id: using credentials from environment variables (AWS_ACCESS_KEY_ID={0}...)",
                    mask(accessKeyId));
        } else {
            LOG.log(Level.INFO, "AWS IAM cloud-id: no env var credentials found, trying instance metadata (IMDS/ECS)");
            String[] imds = fetchAwsImdsCredentials();
            accessKeyId = imds[0];
            secretKey = imds[1];
            sessionToken = imds[2];
            LOG.log(Level.INFO, "AWS IAM cloud-id: obtained credentials from metadata (AccessKeyId={0}..., hasSessionToken={1})",
                    new Object[]{mask(accessKeyId), sessionToken != null && !sessionToken.isEmpty()});
        }

        if (accessKeyId == null || secretKey == null) {
            throw new Exception("Could not obtain AWS credentials from environment or instance metadata");
        }

        String cloudId = signStsGetCallerIdentity(accessKeyId, secretKey, sessionToken);
        LOG.log(Level.INFO, "AWS IAM cloud-id: generated successfully (length={0})", cloudId.length());
        if (LOG.isLoggable(Level.FINE)) {
            String decoded = new String(Base64.getDecoder().decode(cloudId), StandardCharsets.UTF_8);
            LOG.log(Level.FINE, "AWS IAM cloud-id (decoded): {0}", decoded);
        }
        return cloudId;
    }

    private static String mask(String s) {
        if (s == null) return "null";
        return s.substring(0, Math.min(4, s.length())) + "****";
    }

    private static String[] fetchAwsImdsCredentials() throws Exception {
        HttpClient http = HttpClient.newBuilder().connectTimeout(HTTP_TIMEOUT).build();

        // ECS task role
        String ecsUri = System.getenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI");
        if (ecsUri != null && !ecsUri.isEmpty()) {
            LOG.log(Level.INFO, "AWS IAM: trying ECS task role credentials (AWS_CONTAINER_CREDENTIALS_RELATIVE_URI set)");
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create("http://169.254.170.2" + ecsUri))
                    .timeout(HTTP_TIMEOUT).GET().build();
            String body = http.send(req, HttpResponse.BodyHandlers.ofString()).body();
            return parseAwsCredsJson(body);
        }

        LOG.log(Level.INFO, "AWS IAM: trying EC2 IMDSv2 credentials");

        // IMDSv2
        HttpRequest tokenReq = HttpRequest.newBuilder()
                .uri(URI.create("http://169.254.169.254/latest/api/token"))
                .header("X-aws-ec2-metadata-token-ttl-seconds", "21600")
                .timeout(HTTP_TIMEOUT)
                .PUT(HttpRequest.BodyPublishers.noBody()).build();
        String imdsToken = http.send(tokenReq, HttpResponse.BodyHandlers.ofString()).body();

        HttpRequest roleReq = HttpRequest.newBuilder()
                .uri(URI.create("http://169.254.169.254/latest/meta-data/iam/security-credentials/"))
                .header("X-aws-ec2-metadata-token", imdsToken)
                .timeout(HTTP_TIMEOUT).GET().build();
        String roleName = http.send(roleReq, HttpResponse.BodyHandlers.ofString()).body().trim();
        LOG.log(Level.INFO, "AWS IAM: found instance role: {0}", roleName);

        HttpRequest credReq = HttpRequest.newBuilder()
                .uri(URI.create("http://169.254.169.254/latest/meta-data/iam/security-credentials/" + roleName))
                .header("X-aws-ec2-metadata-token", imdsToken)
                .timeout(HTTP_TIMEOUT).GET().build();
        String credJson = http.send(credReq, HttpResponse.BodyHandlers.ofString()).body();
        return parseAwsCredsJson(credJson);
    }

    private static String[] parseAwsCredsJson(String json) {
        return new String[]{
                jsonValue(json, "AccessKeyId"),
                jsonValue(json, "SecretAccessKey"),
                jsonValue(json, "Token")
        };
    }

    private static String signStsGetCallerIdentity(String accessKeyId, String secretKey, String sessionToken) throws Exception {
        String stsHost = "sts.amazonaws.com";
        String payload = "Action=GetCallerIdentity&Version=2011-06-15";
        String payloadHash = sha256Hex(payload);

        SimpleDateFormat df = new SimpleDateFormat("yyyyMMdd'T'HHmmss'Z'");
        df.setTimeZone(TimeZone.getTimeZone("UTC"));
        String amzDate = df.format(new Date());
        String dateStamp = amzDate.substring(0, 8);

        // Canonical headers (lowercase, sorted alphabetically) — used for signing
        TreeMap<String, String> canonicalHeaderMap = new TreeMap<>();
        canonicalHeaderMap.put("content-type", "application/x-www-form-urlencoded; charset=utf-8");
        canonicalHeaderMap.put("host", stsHost);
        canonicalHeaderMap.put("x-amz-date", amzDate);
        if (sessionToken != null && !sessionToken.isEmpty()) {
            canonicalHeaderMap.put("x-amz-security-token", sessionToken);
        }

        StringBuilder canonicalHeaders = new StringBuilder();
        StringBuilder signedHeaders = new StringBuilder();
        for (Map.Entry<String, String> e : canonicalHeaderMap.entrySet()) {
            canonicalHeaders.append(e.getKey()).append(":").append(e.getValue()).append("\n");
            if (signedHeaders.length() > 0) signedHeaders.append(";");
            signedHeaders.append(e.getKey());
        }

        String canonicalRequest = "POST\n/\n\n" + canonicalHeaders + "\n" + signedHeaders + "\n" + payloadHash;

        String credentialScope = dateStamp + "/us-east-1/sts/aws4_request";
        String stringToSign = "AWS4-HMAC-SHA256\n" + amzDate + "\n" + credentialScope + "\n" + sha256Hex(canonicalRequest);

        byte[] signingKey = getSignatureKey(secretKey, dateStamp, "us-east-1", "sts");
        String signature = bytesToHex(hmacSha256(signingKey, stringToSign));

        String authorization = "AWS4-HMAC-SHA256 Credential=" + accessKeyId + "/" + credentialScope
                + ", SignedHeaders=" + signedHeaders + ", Signature=" + signature;

        // Match official akeyless-js-cloud-id format exactly (see cloudid.js):
        // sts_request_url, sts_request_body, sts_request_headers are each base64-encoded strings.
        // Top-level cloud_id = base64(JSON.stringify(obj)).
        String stsUrl = "https://sts.amazonaws.com/";
        LinkedHashMap<String, String> requestHeaders = new LinkedHashMap<>();
        requestHeaders.put("Authorization", authorization);
        requestHeaders.put("Content-Length", String.valueOf(payload.length()));
        requestHeaders.put("Content-Type", "application/x-www-form-urlencoded; charset=utf-8");
        requestHeaders.put("Host", stsHost);
        requestHeaders.put("X-Amz-Date", amzDate);
        if (sessionToken != null && !sessionToken.isEmpty()) {
            requestHeaders.put("X-Amz-Security-Token", sessionToken);
        }

        // Headers as JSON object with array values (e.g. {"Authorization":["AWS4-..."], ...}), then base64
        StringBuilder headersJson = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, String> e : requestHeaders.entrySet()) {
            if (!first) headersJson.append(",");
            headersJson.append("\"").append(e.getKey()).append("\":[\"").append(escapeJson(e.getValue())).append("\"]");
            first = false;
        }
        headersJson.append("}");
        String stsRequestHeadersB64 = Base64.getEncoder().encodeToString(headersJson.toString().getBytes(StandardCharsets.UTF_8));
        String stsRequestUrlB64 = Base64.getEncoder().encodeToString(stsUrl.getBytes(StandardCharsets.UTF_8));
        String stsRequestBodyB64 = Base64.getEncoder().encodeToString(payload.getBytes(StandardCharsets.UTF_8));

        StringBuilder obj = new StringBuilder("{");
        obj.append("\"sts_request_method\":\"POST\",");
        obj.append("\"sts_request_url\":\"").append(stsRequestUrlB64).append("\",");
        obj.append("\"sts_request_body\":\"").append(stsRequestBodyB64).append("\",");
        obj.append("\"sts_request_headers\":\"").append(stsRequestHeadersB64).append("\"");
        obj.append("}");
        return Base64.getEncoder().encodeToString(obj.toString().getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] getSignatureKey(String key, String dateStamp, String region, String service) throws Exception {
        byte[] kSecret = ("AWS4" + key).getBytes(StandardCharsets.UTF_8);
        byte[] kDate = hmacSha256(kSecret, dateStamp);
        byte[] kRegion = hmacSha256(kDate, region);
        byte[] kService = hmacSha256(kRegion, service);
        return hmacSha256(kService, "aws4_request");
    }

    // ── Azure AD ─────────────────────────────────────────────────────────

    public static String generateAzureCloudId() throws Exception {
        HttpClient http = HttpClient.newBuilder().connectTimeout(HTTP_TIMEOUT).build();
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create("http://169.254.169.254/metadata/identity/oauth2/token"
                        + "?api-version=2018-02-01&resource=https://management.azure.com/"))
                .header("Metadata", "true")
                .timeout(HTTP_TIMEOUT).GET().build();
        HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() != 200) {
            throw new Exception("Azure IMDS returned HTTP " + resp.statusCode() + ": " + resp.body());
        }
        String token = jsonValue(resp.body(), "access_token");
        if (token == null || token.isEmpty()) {
            throw new Exception("No access_token in Azure IMDS response");
        }
        return token;
    }

    // ── GCP ──────────────────────────────────────────────────────────────

    public static String generateGcpCloudId(String audience) throws Exception {
        if (audience == null || audience.isBlank()) {
            audience = "akeyless.io";
        }
        HttpClient http = HttpClient.newBuilder().connectTimeout(HTTP_TIMEOUT).build();
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create("http://metadata.google.internal/computeMetadata/v1/instance/"
                        + "service-accounts/default/identity?audience=" + audience + "&format=full"))
                .header("Metadata-Flavor", "Google")
                .timeout(HTTP_TIMEOUT).GET().build();
        HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() != 200) {
            throw new Exception("GCP metadata returned HTTP " + resp.statusCode() + ": " + resp.body());
        }
        return resp.body().trim();
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    private static byte[] hmacSha256(byte[] key, String data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
    }

    private static String sha256Hex(String data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(data.getBytes(StandardCharsets.UTF_8));
        return bytesToHex(hash);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    /** Minimal JSON string value extractor (no dependency on Gson/Jackson). */
    static String jsonValue(String json, String key) {
        String search = "\"" + key + "\"";
        int idx = json.indexOf(search);
        if (idx < 0) return null;
        int colon = json.indexOf(':', idx + search.length());
        if (colon < 0) return null;
        int start = json.indexOf('"', colon + 1);
        if (start < 0) return null;
        int end = json.indexOf('"', start + 1);
        if (end < 0) return null;
        return json.substring(start + 1, end);
    }

    private static String escapeJson(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
