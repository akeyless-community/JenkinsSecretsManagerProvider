# Akeyless Credentials Provider

A Jenkins plugin that provides **CredentialsProvider** integration with [Akeyless](https://www.akeyless.io/), so secrets stored in Akeyless appear as Jenkins credentials and can be used in pipelines with `credentials('id')` — similar to the [AWS Secrets Manager Credentials Provider](https://plugins.jenkins.io/aws-secrets-manager-credentials-provider/).

## Features

- **Read-only** view of Akeyless static secrets as Jenkins credentials
- **CredentialsProvider** API support: credentials appear in the global store and in pipeline `credentials()` / `withCredentials`
- **Same authentication methods** as the [Akeyless Jenkins plugin](https://plugins.jenkins.io/akeyless/): API Key, AWS IAM, Azure AD, GCP, Kubernetes, Universal Identity, Certificate, Email (t-Token)
- Optional **path prefix** to limit which secrets are listed
- **Tag-based credential types**: use Akeyless tags to map secrets to Secret Text, Username/Password, SSH Key, Certificate, or Secret File

## Requirements

- Jenkins 2.479.3 or later
- [Akeyless plugin](https://plugins.jenkins.io/akeyless/) (for Akeyless authentication credentials)

## Installation

1. Install the **Akeyless** plugin (Manage Jenkins → Plugins).
2. Add at least one **Akeyless credential** (Manage Jenkins → Credentials → Add, then choose one of: Akeyless Access Key, Akeyless Certificate, Akeyless Cloud Provider, Akeyless Universal Identity, Akeyless t-Token, or Username with password for Email).
3. Install **Akeyless Credentials Provider** (this plugin).
4. Configure: **Manage Jenkins → Configure System** → find **Akeyless Credentials Provider** and set:
   - **Akeyless URL**: Your Akeyless gateway URL including `/api/v2` (e.g. `https://my-gateway.akeyless.io/api/v2`).
   - **Akeyless credential**: Choose the credential that authenticates to Akeyless. This dropdown lists credentials created with the Akeyless plugin (Akeyless Access Key, Akeyless Certificate, Akeyless Cloud, etc.). **If the list is empty**, add one first under **Manage Jenkins → Credentials → (global) → Add** and create an Akeyless credential, then return here and select it.
   - **Path prefix (optional)**: Leave empty to list all static secrets, or set a path (e.g. `/jenkins/prod`) to limit which secrets are exposed.
   - **Skip SSL verification**: Enable only for testing with self-signed certificates.
   Click **Save**.

**When does Jenkins call Akeyless?** Jenkins contacts Akeyless when it needs to list or resolve credentials: e.g. when you open **Manage Jenkins → Credentials** (or the global credentials list), when you open the **Akeyless** store, or when a pipeline runs and uses `credentials('id')`. In the Jenkins log you should see lines like `Akeyless Credentials Provider: listing secrets from Akeyless` and `listed N credential(s) from Akeyless`. If you see `config null or not configured` or `could not build client`, check that URL and Akeyless credential are set and the credential exists.

## Usage

### Tagging secrets in Akeyless

For a secret to appear as a specific Jenkins credential type, tag it in Akeyless with:

| Jenkins type        | Tag key                 | Tag value           | Optional tags                          |
|---------------------|-------------------------|---------------------|----------------------------------------|
| Secret Text         | `jenkins:credentials:type` | `string`            | —                                      |
| Username/Password   | `jenkins:credentials:type` | `usernamePassword`  | `jenkins:credentials:username` = username |
| SSH User Private Key| `jenkins:credentials:type` | `sshUserPrivateKey` | `jenkins:credentials:username`        |
| Certificate         | `jenkins:credentials:type` | `certificate`       | —                                      |
| Secret File         | `jenkins:credentials:type` | `file`              | `jenkins:credentials:filename`        |

If no `jenkins:credentials:type` tag is set, the secret is treated as **Secret Text**.

Credential IDs are **relative to the path prefix** when one is set. With path prefix `/CICD/jenkins`, a secret at `/CICD/jenkins/apikey` gets ID **`apikey`**, and a secret at `/CICD/jenkins/test/test3/jenkinsai` gets ID **`test/test3/jenkinsai`**. With no path prefix, the full path is used (e.g. `/CICD/jenkins/apikey` → `CICD/jenkins/apikey`). You can confirm the ID in **Manage Jenkins → Credentials** or in the credential picker when editing a pipeline.

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

- **Akeyless URL**: Gateway URL including `/api/v2` (e.g. `https://my-gateway.akeyless.io/api/v2`).
- **Akeyless authentication**: A Jenkins credential that authenticates to Akeyless (from the Akeyless plugin).
- **Path prefix (optional)**: Only list static secrets under this path (e.g. `/jenkins/prod`).
- **Skip SSL verification**: Enable only for development/testing.

## Configuration as Code (CasC)

Example:

```yaml
unclassified:
  akeylessCredentialsProviderConfig:
    akeylessUrl: "https://my-gateway.akeyless.io/api/v2"
    credentialId: "akeyless-api-key-cred"
    pathPrefix: "/jenkins"
    skipSslVerification: false
```

## Building

```bash
mvn clean package
```

The `.hpi` file is in `target/akeyless-credentials-provider-*.hpi`.

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.
