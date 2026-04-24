# Ruby Dependency Audit

## Detect

- `Gemfile`
- `Gemfile.lock`
- vendored gems or copied engines

## Preferred Audit Paths

```bash
bundle audit check
bundle list
```

## What To Check

- vulnerable gems and transitive chains
- Rails and Rack version health
- gem source trust and private registries
- groups such as `development` and `test` leaking into deploy artifacts
- parser, file upload, XML, archive, markdown, and auth gems

## Common High-Risk Cases

- old Rails chains brought in by internal engines
- admin or debug gems reachable in staging or production
- lock file says one thing while Docker build installs another bundle set

## Reporting Notes

- Record the gem group when relevant.
- Mention if the vulnerable gem is part of an engine or shared internal package.
