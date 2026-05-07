# Akeyless Credentials Provider

A Jenkins plugin that provides **CredentialsProvider** integration with [Akeyless](https://www.akeyless.io/), so secrets stored in Akeyless appear as Jenkins credentials and can be used in pipelines with `credentials('id')`

## Features

- **Read-only** view of Akeyless secrets as Jenkins credentials
- **CredentialsProvider** API support: credentials appear in the global store and in pipeline `credentials()` / `withCredentials`
- **User-provided paths**: configure **folder path only** (the plugin calls **list-items** recursively to discover secrets — no manual name list), or **folder + secret names**, or **full secret paths**. **describe-item** reads item tags when building the credential list; when a job uses a credential, the plugin runs **describe-item** again, then **get-secret-value**, **get-dynamic-secret-value**, **get-rotated-secret-value**, or **get-certificate-value** depending on the item type (missing items fail like a 404).
- **Cache** (same idea as the AWS Secrets Manager provider): optionally cache recursive **list-items** results for folder-only discovery. Enabled by default with a fixed **5 minute** TTL (not configurable). Disable **Cache** during development so every Jenkins credentials refresh triggers a fresh **list-items** call. **describe-item** for tags still runs when Jenkins rebuilds the credential list.
- **Folder path safety**: **`/` or `//` alone** is rejected (that would scope the entire vault); use a concrete path such as `/CICD/jenkins/secrets`.
- **Jenkins credential types from Akeyless tags** (same keys as [AWS Secrets Manager Credentials Provider](https://plugins.jenkins.io/aws-secrets-manager-credentials-provider/)): set tags on each Akeyless item so Jenkins maps it to Secret text, Username/password, SSH key, Certificate, or Secret file.
- **JSON secret body** (optional): for username/password or SSH credentials, store JSON in the secret and set tag `jenkins:credentials:valueFormat=json` so username/password (or private key/passphrase) are read from one secret—pipeline bindings then expose the usual variables (`*_USR`, `*_PSW`, etc.).
- **Standalone** — authenticates with your chosen method (API Key, Kubernetes, GCP, etc.) stored in the plugin config. No external plugin dependencies.

## Requirements

- Jenkins 2.479.3 or later

## Installation

1. Install **Akeyless Credentials Provider** (this plugin).
2. Configure: **Manage Jenkins → Configure System** → find **Akeyless Credentials Provider** and set:
   - **Akeyless URL**: Your Akeyless gateway API URL (used as-is; no suffix is added). If behind a load balancer, use the full URL including path (e.g. `https://gateway.example.com/api/v2`).
   - **Access ID**: Your Akeyless access ID (e.g. `p-abc123`), if required by your auth method.
   - **Authentication Method**: e.g. API Key, Kubernetes, GCP, etc.
   - **Cache** (on by default): when enabled, folder-only **list-items** responses are cached for 5 minutes (same duration message as the AWS credentials provider). Turn off for development if you need a fresh listing every time the credentials UI refreshes.
   - **Folder path** only (e.g. `/CICD/jenkins/secrets`): leave **Secret names** and **Secret paths** empty — the plugin discovers items under that folder via **list-items** (recursive). Credential IDs are derived from each item path (typically the last segment), same as when using explicit names.
   - Or **Folder path** + **Secret names** (one per line): full path = folder + `/` + name; use `credentials('shortName')` as today.
   - Or **Secret paths**: full path per line when not using the folder modes above.
   Click **Save**.

**When does Jenkins call Akeyless?** When building the credential list (e.g. opening **Manage Jenkins → Credentials**), the plugin calls **list-items** on each refresh if **Cache** is off, or reuses a cached **list-items** result for up to 5 minutes if **Cache** is on (folder-only mode). **describe-item** runs per item when tags are needed. When a job resolves a credential, the plugin calls **describe-item**, then the appropriate fetch API for that item’s type.

### Tags on Akeyless items (same convention as AWS)

Set these **tags on the Akeyless item** (not only in the secret value):

| Tag | Values | Purpose |
|-----|--------|---------|
| `jenkins:credentials:type` | `string`, `usernamePassword`, `sshUserPrivateKey`, `certificate`, `file` | Jenkins credential kind |
| `jenkins:credentials:username` | text | Username for `usernamePassword` and `sshUserPrivateKey` (when not using JSON body) |
| `jenkins:credentials:filename` | text | Optional file name for `file` type |
| `jenkins:credentials:valueFormat` | `json` (optional) | If set, or if the secret value looks like JSON `{...}`, username/password or SSH fields are parsed from the secret **value** |

If `jenkins:credentials:type` is missing, the plugin defaults to **`string`** (Secret text).

#### Supported credential types and examples

1. **Secret text** (`string`)
   - Tags:
     - `jenkins:credentials:type=string` (or omit this tag and `string` is used by default)
   - Secret value example: `my-api-token-value`
   - Jenkins usage: `withCredentials([string(credentialsId: 'my-id', variable: 'TOKEN')])`

2. **Username and password** (`usernamePassword`)
   - Tags (plain value mode):
     - `jenkins:credentials:type=usernamePassword`
     - `jenkins:credentials:username=joe`
   - Secret value example (plain): `supersecret`
   - Tags (JSON mode, recommended):
     - `jenkins:credentials:type=usernamePassword`
     - `jenkins:credentials:valueFormat=json`
   - Secret value example (JSON): `{"username":"joe","password":"supersecret"}`
   - Jenkins binding variables behave like AWS plugin, for example:
     - `ARTIFACTORY=joe:supersecret`
     - `ARTIFACTORY_USR=joe`
     - `ARTIFACTORY_PSW=supersecret`

3. **SSH username with private key** (`sshUserPrivateKey`)
   - Tags (plain value mode):
     - `jenkins:credentials:type=sshUserPrivateKey`
     - `jenkins:credentials:username=git`
   - Secret value example (plain): full private key PEM text (`-----BEGIN ...-----`)
   - Tags (JSON mode, recommended):
     - `jenkins:credentials:type=sshUserPrivateKey`
     - `jenkins:credentials:valueFormat=json`
   - Secret value example (JSON): `{"username":"git","privateKey":"-----BEGIN...","passphrase":""}`
   - Jenkins binding variables include, for example:
     - `KEY=/tmp/path/to/private/key`
     - `KEY_USR=git`

4. **Secret file** (`file`)
   - Tags:
     - `jenkins:credentials:type=file`
     - Optional: `jenkins:credentials:filename=settings.xml`
   - Secret value example: file content (text or binary supported by Akeyless item value type)
   - Jenkins usage: `withCredentials([file(credentialsId: 'my-file', variable: 'FILE_PATH')])`

5. **Certificate** (`certificate`)
   - Tags:
     - `jenkins:credentials:type=certificate`
   - Secret value examples:
     - PKCS#12 content
     - Or certificate/key pair (when returned by Akeyless certificate APIs)
   - Jenkins usage: certificate credential in jobs/plugins that request `StandardCertificateCredentials`

#### JSON notes for `usernamePassword` and `sshUserPrivateKey`

- Set tag `jenkins:credentials:valueFormat=json` to force JSON parsing.
- If `valueFormat` is not set, JSON is still parsed automatically when the value clearly looks like `{...}`.
- Username/password JSON also accepts key aliases:
  - username: `username`, `user`, `usr`
  - password: `password`, `psw`, `secret`, `passwd`
- SSH JSON also accepts private key aliases: `privateKey`, `private_key`, `key`.
- If username is missing in JSON, `jenkins:credentials:username` is used as fallback.

**IAM / access:** the Akeyless identity must be allowed to **list** (when using folder-only discovery), **describe**, and fetch secrets via **get-secret-value**, **get-dynamic-secret-value**, **get-rotated-secret-value**, or **get-certificate-value** as appropriate for those items.

## Usage

**Folder path only:** Set **Folder path** and leave **Secret names** and **Secret paths** empty. The plugin lists items under the folder and registers credentials (IDs usually match the last path segment). In jobs, use `credentials('same-as-before')` for those IDs.

**Folder path + Secret names:** Same as before — full path = folder + name; values are fetched with describe-first and type-specific APIs.

**Secret paths (optional):** Full paths (one per line). Each Akeyless item appears **once** in Jenkins; the credential id is usually the **last path segment** (same as folder + names). If two items share the same last segment, the second uses the **full path** as id.

Confirm the IDs in **Manage Jenkins → Credentials** or in the credential picker when editing a pipeline.

### Pipeline examples

**Declarative:**

```groovy
pipeline {
  agent any
  environment {
    API_KEY = credentials('my-api-key')
  }
  stages {
    stage('Build') {
      steps {
        sh 'echo Building...'
      }
    }
  }
}
```

**Scripted:**

```groovy
node {
  withCredentials([string(credentialsId: 'my-api-key', variable: 'API_KEY')]) {
    sh 'echo $API_KEY'
  }
}
```

## Configuration

- **Akeyless URL**: Gateway API URL (used as-is; no suffix added). Example: `https://my-gateway.akeyless.io` or `https://gateway.example.com/api/v2`.
- **Access ID**: Your Akeyless access ID (e.g. `p-abc123`), if required by your auth method.
- **Authentication Method**: API Key, Kubernetes, GCP, Azure AD, etc.
- **Secret paths**: One Akeyless secret path per line (e.g. `/CICD/jenkins/apikey`). Only get-secret-value is used.

## Configuration as Code (CasC)

Example:

```yaml
unclassified:
  akeylessCredentialsProviderConfig:
    akeylessUrl: "https://my-gateway.akeyless.io"
    accessId: "p-abc123"
    cache: true
    secretPaths: |
      /CICD/jenkins/apikey
      /CICD/jenkins/db-password
```

## Troubleshooting

### `failed to decode api key` / `illegal base64 data at input byte 1`

The Akeyless gateway Base64-decodes the **access key**. This error almost always means the wrong value was pasted into **Access Key** under **API Key** auth:

- **Access ID** looks like `p-…` (with hyphens). If that string is pasted into **Access Key**, the second character is often `-`, which is **not** valid Base64 — hence *illegal base64 data at input byte 1*.
- Use **Access ID** only in the global **Access ID** field; put the **separate long secret** from Akeyless in **Access Key**.
- Remove accidental **spaces**, **newlines**, or **quotes** around the key (the plugin strips normal whitespace from the key when authenticating).
- If the customer uses **AWS IAM** auth, they should not need an access key at all; if this error still appears, confirm **Authentication Method** is set to **AWS IAM** and not **API Key** with empty or wrong fields.

### No credentials listed

Authentication must succeed before **describe-item** / **list-items** run. Check **Manage Jenkins → System log** for `Akeyless: authentication failed` or API errors right after saving configuration.

## Building

```bash
mvn clean package
```

The `.hpi` file is in `target/akeyless-credentials-provider-*.hpi`.

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.
