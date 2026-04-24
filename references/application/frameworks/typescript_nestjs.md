# NestJS Security Reference

## Identification Features

```bash
grep -r "@Module\|@Controller\|@Injectable" --include="*.ts"
grep -r "NestFactory\.create\|APP_GUARD\|ValidationPipe" --include="*.ts"
grep -r "@UseGuards\|@Public\|CanActivate" --include="*.ts"
```

Common file patterns: `*.module.ts`, `*.controller.ts`, `*.service.ts`, `main.ts`, `guards/`, `dto/`.

---

## High-Risk Framework Surfaces

### 1. Guard Coverage Gaps

- global guards bypassed by `@Public()`
- controller methods missing `@UseGuards` where class-level assumptions fail
- websocket gateways and microservice handlers not covered by HTTP guard logic

### 2. Validation Pipe Gaps

- no global `ValidationPipe`
- `whitelist` and `forbidNonWhitelisted` disabled
- DTOs missing decorators, allowing mass assignment through extra fields

### 3. Serialization and Exposure

- entities returned directly from controllers
- interceptors omitted, exposing internal fields
- class-transformer assumptions without `@Exclude` / `@Expose`

### 4. Configuration and CORS

- `enableCors()` with broad origins and credentials
- Swagger or GraphQL playground exposed without auth
- custom exception filters leaking internals

---

## Dangerous Patterns

```typescript
app.useGlobalPipes(new ValidationPipe());

@Post()
create(@Body() body: any) {
  return this.usersService.create(body);
}

@Public()
@Get("admin")
getAdminData() { ... }
```

Better:

```typescript
app.useGlobalPipes(new ValidationPipe({
  whitelist: true,
  forbidNonWhitelisted: true,
  transform: true,
}));
```

---

## Detection Commands

```bash
grep -rn "ValidationPipe\|whitelist\|forbidNonWhitelisted" --include="*.ts"
grep -rn "@UseGuards\|APP_GUARD\|@Public\|CanActivate" --include="*.ts"
grep -rn "@Body()\|@Query()\|@Param()" --include="*.ts"
grep -rn "@WebSocketGateway\|@SubscribeMessage" --include="*.ts"
grep -rn "enableCors\|SwaggerModule\|GraphQLModule" --include="*.ts"
```

---

## Audit Questions

- Do HTTP, websocket, and message-based entry points enforce the same auth model?
- Are DTOs narrow and decorator-backed, or are plain objects accepted?
- Are entities serialized directly back to clients?
- Can `@Public()` or route metadata punch holes through assumed global protection?
