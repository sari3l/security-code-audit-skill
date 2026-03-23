# .NET and C# Dependency Audit

## Detect

- `*.csproj`
- `*.sln`
- `Directory.Packages.props`
- `packages.lock.json`
- `NuGet.Config`

## Preferred Audit Paths

```bash
dotnet list package --vulnerable --include-transitive
dotnet list package --outdated
```

## What To Check

- vulnerable direct and transitive NuGet packages
- central package management drift across projects
- custom or private NuGet feeds
- ASP.NET Core, serializer, auth, archive, image, and HTTP packages
- runtime support level and target framework age

## Common High-Risk Cases

- one project in the solution uses a newer fixed version while another still inherits the old one
- `packages.lock.json` is absent, so restore behavior can drift
- build-only packages land in published artifacts through container or publish misconfiguration

## Reporting Notes

- Record the project path that brings in the vulnerable package.
- Mention whether the package is inherited from central package props or project-local reference.
