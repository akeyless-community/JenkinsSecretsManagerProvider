# Akeyless Credentials Provider

A Jenkins plugin that provides **CredentialsProvider** integration with [Akeyless](https://www.akeyless.io/), so secrets stored in Akeyless appear as Jenkins credentials and can be used in pipelines with `credentials('id')`

## Features

- **Read-only** view of Akeyless static secrets as Jenkins credentials
- **CredentialsProvider** API support: credentials appear in the global store and in pipeline `credentials()` / `withCredentials`
- **Standalone** — authenticates directly with API Key (access_id / access_key) stored in the plugin config (encrypted). No external plugin dependencies.
- Optional **path prefix** to limit which secrets are listed
- **Tag-based credential types**: use Akeyless tags to map secrets to Secret Text, Username/Password, SSH Key, Certificate, or Secret File

## Requirements

- Jenkins 2.479.3 or later

## Installation

1. Install **Akeyless Credentials Provider** (this plugin).
2. Configure: **Manage Jenkins → Configure System** → find **Akeyless Credentials Provider** and set:
   - **Akeyless URL**: Your Akeyless gateway URL including `/api/v2` (e.g. `https://my-gateway.akeyless.io/api/v2`).
   - **Access ID**: Your Akeyless access ID (e.g. `p-abc123`).
   - **Access Key**: Your Akeyless access key (stored encrypted by Jenkins).
   - **Path prefix (optional)**: Leave empty to list all static secrets, or set a path (e.g. `/jenkins/prod`) to limit which secrets are exposed.
   Click **Save**.

**When does Jenkins call Akeyless?** Jenkins contacts Akeyless when it needs to list or resolve credentials: e.g. when you open **Manage Jenkins → Credentials**, when a pipeline runs and uses `credentials('id')`, etc. In the Jenkins log you should see lines like `Akeyless Credentials Provider: listing secrets from Akeyless` and `listed N credential(s) from Akeyless`.

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
- **Access ID**: Your Akeyless access ID (e.g. `p-abc123`).
- **Access Key**: Your Akeyless access key (stored encrypted by Jenkins).
- **Path prefix (optional)**: Only list static secrets under this path (e.g. `/jenkins/prod`).

## Configuration as Code (CasC)

Example:

```yaml
unclassified:
  akeylessCredentialsProviderConfig:
    akeylessUrl: "https://my-gateway.akeyless.io/api/v2"
    accessId: "p-abc123"
    accessKey: "your-access-key"
    pathPrefix: "/jenkins"
```

## Building

```bash
mvn clean package
```

The `.hpi` file is in `target/akeyless-credentials-provider-*.hpi`.

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.
