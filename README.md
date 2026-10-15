# lutherauth-sdk-go

This SDK provides Go utilities to extract and validate JWT claims issued by
[LutherAuth](https://github.com/luthersystems/lutherauth), the centralized
authentication service powering identity and access control for the Luther
Platform.

LutherAuth issues secure RS256-signed JWTs containing user metadata and access
roles. This SDK offers a high-level interface for verifying those tokens from
GRPC contexts, HTTP cookies, or raw headers, and supports common integration
scenarios like:

- Verifying signed tokens using JWKs published by an external identity provider
- Validating CSRF protection using nonces
- Implementing fake claims for local development
- Enforcing API key presence before extracting claims

## Features

- JWT claim extraction and validation via GRPC metadata or HTTP cookies
- JWK (JSON Web Key) support with caching and configurable source resolution
- Supports both authenticated and fake tokens for test/dev workflows
- Pre-validation of API keys before extracting user claims
- Lightweight and dependency-minimized for embedding into services

## Installing

```bash
go get github.com/luthersystems/lutherauth-sdk-go
```

## Usage

### Basic Claim Validation

```go
import (
    "context"
    "github.com/luthersystems/lutherauth-sdk-go/claims"
    "github.com/sirupsen/logrus"
)

// Setup once
claimGetter := claims.NewJWKClaims(
    claims.NewAuthTokenGetter(),
    nil, // optional CSRF nonce getter
    func(ctx context.Context) *logrus.Entry {
        return logrus.NewEntry(logrus.StandardLogger())
    },
)

// Inside GRPC handler
func MyHandler(ctx context.Context) error {
    userClaims, err := claimGetter.Claims(ctx)
    if err != nil {
        return fmt.Errorf("unauthorized: %w", err)
    }
    fmt.Println("user:", userClaims.Subject)
    return nil
}
```

### Local Development (Fake Claims)

```go
token := claims.NewFakeAuthToken(&jwt.Claims{
    Subject: "test-user",
    Issuer: "local-dev",
    Audience: []string{"my-app"},
})

getter := claims.NewFakeAuthClaims(
    claims.NewRawTokenGetter("authorization", true),
)
ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs(
    "authorization", token,
))
claims, err := getter.Claims(ctx)
```

## Token Sources Supported

| Source Type    | Description                           |
| -------------- | ------------------------------------- |
| GRPC Metadata  | Bearer or raw token in metadata       |
| HTTP Cookies   | Reads from cookie headers             |
| Custom Headers | e.g., `X-API-Key`, for API key checks |

## Pre-Validation with API Keys

To enforce API key validation before allowing claim extraction:

```go
preValidator := claims.NewAPIKeyValidator(
    claims.NewRawTokenGetter("x-api-key", true),
    []string{"valid-key-1", "valid-key-2"},
)

getter := claims.AddPreValidator(
    claims.NewJWKClaims(...),
    preValidator,
)
```

## Testing

```bash
make go-test
```

## Internal Modules

- `claims/`: Core logic for retrieving and validating claims
- `jwk/`: JWK key management and RS256 signature verification
- `jwt/`: Structs and helpers for user claims and token duplication

## Reference

LutherAuth is designed to interoperate with OIDC-compliant identity providers,
including Cognito and AzureAD. It issues signed JWTs used for session
authentication across the Luther Platform. These tokens are verified
by services using this SDK to authorize and personalize user interactions.

See full documentation at: [GoDoc](https://pkg.go.dev/github.com/luthersystems/lutherauth-sdk-go)

## Development

The SDK is used by services deployed across the Luther ecosystem. It adheres
to strict security and logging practices to ensure auditability and
consistency. All errors must be returned as gRPC `status.Error`.

To contribute, follow the [standard Git workflow](https://www.atlassian.com/git/tutorials/comparing-workflows/feature-branch-workflow). Ensure tests pass with:

```bash
make go-test
```

## Versioning

This SDK uses [semantic versioning](https://semver.org/) for releases. For
pre-release builds, use `-SNAPSHOT` suffixes.
