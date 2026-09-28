// Pattern catalog for recon.mjs. Plain regexes over source lines, so they are hints, not proof: recon reports every hit
// with file:line and the skill confirms each one by reading the code. Add a framework by adding rows here.
// Route patterns capture { method, path } through named groups. `exts` limits a pattern to file extensions.

const JS = ['.js', '.mjs', '.cjs', '.ts', '.mts', '.cts', '.jsx', '.tsx'];
const CS = ['.cs'];
const GO = ['.go'];
const PY = ['.py'];
const JVM = ['.java', '.kt'];
const RB = ['.rb'];
const PHP = ['.php'];
const RS = ['.rs'];

// Receivers that are HTTP clients, so `axios.get('/x')` is an outbound call, not a route.
export const CLIENT_RECEIVERS = /^(axios|http|https|client|httpClient|api|apiClient|fetcher|got|request|superagent|ky|instance|service|svc|this|cache|map|params|headers|searchParams|cookies|store|redis|kv|env|db|repo|session|localStorage|sessionStorage|url|formData|res|response|req|ctx\.req)$/i;

export const ROUTES = [
  // JS/TS: Express, Koa router, Hono, Fastify shorthand, itty-router, Elysia
  { framework: 'js-router', exts: JS, re: /\b(?<recv>[A-Za-z_$][\w$]*)\.(?<method>get|post|put|patch|delete|all|options|head)\(\s*(['"`])(?<path>\/[^'"`]*)\3/g },
  { framework: 'fastify', exts: JS, re: /\.route\(\s*\{[^}]*method:\s*['"](?<method>\w+)['"][^}]*url:\s*['"](?<path>[^'"]+)/g },
  // NestJS (prefix from @Controller is added by recon)
  { framework: 'nestjs', exts: JS, re: /@(?<method>Get|Post|Put|Patch|Delete|All)\(\s*(?:['"`](?<path>[^'"`]*)['"`])?\s*\)/g },
  // ASP.NET Core minimal APIs and controllers (class-level [Route] prefix is added by recon)
  { framework: 'aspnet-minimal', exts: CS, re: /\.Map(?<method>Get|Post|Put|Patch|Delete)\(\s*"(?<path>[^"]*)"/g },
  { framework: 'aspnet-minimal', exts: CS, re: /\.MapMethods\(\s*"(?<path>[^"]*)"\s*,\s*new\s*\[\]\s*\{\s*"(?<method>\w+)"/g },
  { framework: 'aspnet-mvc', exts: CS, re: /\[Http(?<method>Get|Post|Put|Patch|Delete)(?:\(\s*"(?<path>[^"]*)"[^\]]*)?\]/g },
  { framework: 'azure-functions', exts: CS, re: /\[HttpTrigger\([^\]]*?Route\s*=\s*"(?<path>[^"]*)"/g },
  // Go: net/http (1.22 "GET /x" patterns), chi, gorilla/mux, gin, echo, fiber
  { framework: 'go-nethttp', exts: GO, re: /\bHandle(?:Func)?\(\s*"(?:(?<method>GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s+)?(?<path>\/[^"]*)"/g },
  { framework: 'go-router', exts: GO, re: /\.(?<method>Get|Post|Put|Patch|Delete|GET|POST|PUT|PATCH|DELETE|Any|Options|OPTIONS)\(\s*"(?<path>\/[^"]*)"/g },
  // Python: FastAPI, Flask, Starlette, Django
  { framework: 'python-decorator', exts: PY, re: /@(?<recv>\w+)\.(?<method>get|post|put|patch|delete|route|api_route|websocket)\(\s*['"](?<path>[^'"]+)/g },
  { framework: 'django', exts: PY, re: /\b(?:re_)?path\(\s*r?['"](?<path>[^'"]*)['"]\s*,/g },
  // Java / Kotlin: Spring, JAX-RS
  { framework: 'spring', exts: JVM, re: /@(?<method>Get|Post|Put|Patch|Delete|Request)Mapping\(\s*(?:(?:value|path)\s*=\s*)?\{?\s*"(?<path>[^"]*)"/g },
  { framework: 'jaxrs', exts: JVM, re: /@Path\(\s*"(?<path>[^"]*)"\s*\)/g },
  // Ruby on Rails routes, Sinatra
  { framework: 'rails', exts: RB, re: /^\s*(?<method>get|post|put|patch|delete)\s+['"](?<path>[^'"]+)/gm },
  // PHP: Laravel, Slim
  { framework: 'laravel', exts: PHP, re: /Route::(?<method>get|post|put|patch|delete|any)\(\s*['"](?<path>[^'"]+)/g },
  // Rust: axum, actix-web, rocket
  { framework: 'axum', exts: RS, re: /\.route\(\s*"(?<path>[^"]+)"\s*,\s*(?<method>get|post|put|patch|delete|any)\(/g },
  { framework: 'actix', exts: RS, re: /#\[(?<method>get|post|put|patch|delete)\(\s*"(?<path>[^"]+)"/g },
  // Cloudflare Workers and other fetch-style handlers: path checks inside the handler
  { framework: 'fetch-handler', exts: JS, re: /pathname\s*(?:===?|\.startsWith\()\s*\(?\s*['"`](?<path>\/[^'"`]*)/g },
  { framework: 'fetch-handler', exts: JS, re: /new URLPattern\(\s*\{\s*pathname:\s*['"`](?<path>[^'"`]+)/g },
];

// Route prefixes that apply to the routes after them in the same file.
export const PREFIXES = [
  { framework: 'nestjs', exts: JS, re: /@Controller\(\s*['"`](?<path>[^'"`]*)['"`]/g, scope: 'class' },
  { framework: 'aspnet-mvc', exts: CS, re: /\[Route\(\s*"(?<path>[^"]*)"\s*\)\][\s\S]{0,300}?\bclass\s+(?<cls>\w+)/g, scope: 'class' },
  { framework: 'aspnet-minimal', exts: CS, re: /(?<var>\w+)\s*=\s*\w+\.MapGroup\(\s*"(?<path>[^"]*)"/g, scope: 'var' },
  { framework: 'go-router', exts: GO, re: /(?<var>\w+)\s*:?=\s*\w+\.Group\(\s*"(?<path>[^"]*)"/g, scope: 'var' },
];

// Non-HTTP entry points: triggers, schedules, consumers, sockets, RPC, GraphQL.
export const ENTRIES = [
  { kind: 'worker:fetch', exts: JS, re: /export\s+default\s*\{[\s\S]{0,200}?\b(?:async\s+)?fetch\s*\(/g, note: 'Workers-style fetch handler: every request reaches it; routing happens inside' },
  { kind: 'worker:fetch', exts: JS, re: /addEventListener\(\s*['"]fetch['"]/g },
  { kind: 'worker:fetch', exts: JS, re: /BunnySDK\.net\.http\.serve\(|Deno\.serve\(|Bun\.serve\(/g, note: 'edge or runtime fetch server: routing happens inside' },
  { kind: 'schedule', exts: JS, re: /\b(?:async\s+)?scheduled\s*\(\s*(?:event|controller|_)/g },
  { kind: 'queue-consumer', exts: JS, re: /\b(?:async\s+)?queue\s*\(\s*batch/g },
  { kind: 'lambda-handler', exts: [...JS, ...PY, ...GO], re: /export\s+(?:const|async function|function)\s+handler\b|def\s+(?:lambda_)?handler\s*\(\s*event|lambda\.Start\(/g },
  { kind: 'nextjs-route', exts: JS, re: /export\s+(?:async\s+)?function\s+(?<method>GET|POST|PUT|PATCH|DELETE)\s*\(/g, note: 'Next.js route handler: path comes from the folder' },
  { kind: 'websocket', exts: [...JS, ...CS, ...GO, ...PY], re: /new\s+WebSocketServer\(|io\.on\(\s*['"]connection|WebSocketPair\(|MapHub<|websocket\.Upgrader|UseWebSockets\(|@\w+\.websocket\(/g },
  { kind: 'grpc', exts: [...CS, ...GO, ...JVM, ...JS], re: /MapGrpcService<|Register\w+Server\(|@GrpcService|server\.addService\(/g },
  { kind: 'graphql', exts: [...JS, ...CS, ...GO, ...PY, ...JVM], re: /new\s+ApolloServer\(|createYoga\(|AddGraphQLServer\(|graphql\.NewSchema|gqlgen|strawberry\.Schema|@QueryMapping|@MutationMapping/g },
  { kind: 'timer', exts: CS, re: /\[TimerTrigger\(|\bAddHostedService<|BackgroundService\b/g },
  { kind: 'queue-consumer', exts: [...CS, ...GO, ...JVM, ...PY, ...JS], re: /\[(?:ServiceBus|Queue|EventHub|Kafka|RabbitMQ)Trigger\(|IConsumer<|@KafkaListener|@RabbitListener|@SqsListener|ReceiveMessage(?:Async)?\(|\.subscribe\(\s*['"]|consumer\.run\(|kafka\.NewReader\(/g },
  { kind: 'cron', exts: [...GO, ...PY, ...JS, ...JVM], re: /cron\.New\(|@Scheduled\(|schedule\.every\(|new\s+CronJob\(|node-cron|@periodic_task/g },
  { kind: 'cli', exts: [...GO, ...PY, ...JS, ...CS], re: /cobra\.Command\{|argparse\.ArgumentParser\(|commander|yargs\(/g },
];

export const AUTH = [
  { tag: 'anonymous', re: /\[AllowAnonymous\]|\.AllowAnonymous\(\)|permitAll\(\)|@PermitAll|@Public\(\)|skipAuth|auth:\s*false|authorizationType:\s*['"]?NONE|AuthorizationLevel\.Anonymous/g },
  { tag: 'require', re: /\[Authorize[^\]]*\]|\.RequireAuthorization\(|@PreAuthorize\(|@Secured\(|@RolesAllowed\(|@UseGuards\(|login_required|permission_required|Depends\(\s*(?:get_current_\w+|verify_\w+|auth\w*)|passport\.authenticate\(|requireAuth|isAuthenticated|ensureAuth|authenticated\(\)/g },
  { tag: 'setup', re: /AddAuthentication\(|AddJwtBearer\(|AddMicrosoftIdentityWebApi\(|FallbackPolicy|UseAuthentication\(|UseAuthorization\(|SecurityFilterChain|app\.use\(\s*(?:auth|jwt|session|passport)|\.Use\(\s*\w*(?:[Aa]uth|JWT|Jwt|Session)\w*/g },
  { tag: 'verify-token', re: /jwt\.verify\(|jwtVerify\(|verifyIdToken\(|jwt\.Parse(?:WithClaims)?\(|ValidateToken\(|decode_token|jwt\.decode\(|Cf-Access-Jwt-Assertion|getServerSession\(|auth\(\)\s*;|clerkMiddleware|withAuth\(/gi },
  { tag: 'signature', re: /createHmac\(|timingSafeEqual\(|hmac\.(?:New|Equal)|HMACSHA256|crypto\.subtle\.verify\(|constructEvent\(|verifySignature|X-Hub-Signature|Stripe-Signature/g },
  { tag: 'api-key', re: /x-api-key|X-API-Key|apiKeyRequired|ApiKeyAuth|api_key_header/g },
  { tag: 'cors', re: /Access-Control-Allow-Origin|AllowAnyOrigin\(\)|AllowCredentials\(\)|cors\(\s*\{?|allowOrigins|CORS_ALLOWED|@CrossOrigin/g },
  { tag: 'csrf', re: /csrf|antiforgery|AntiForgery|ValidateAntiForgeryToken|SameSite/gi },
  { tag: 'rate-limit', re: /rateLimit|RateLimiter|AddRateLimiter|throttle|limiter\.|Ratelimit/g },
];

export const OUTBOUND = [
  { kind: 'http', re: /(?<![.\w])fetch\(\s*(?!['"`]\/)|axios(?:\.\w+)?\(|\bgot\(|\bky\.|HttpClient\b|IHttpClientFactory|http\.(?:Get|Post|NewRequest(?:WithContext)?)\(|requests\.(?:get|post|put|delete|request)\(|httpx\.|RestTemplate|WebClient\.|Refit|urllib\.request/g },
  { kind: 'binding', re: /\benv\.[A-Z][A-Z0-9_]*\.(?:fetch|get|put|delete|list|prepare|send|idFromName)\(/g, note: 'Cloudflare binding (service, KV, D1, R2, queue, Durable Object)' },
  { kind: 'sql', re: /\b(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+[\w"`[]/g },
  { kind: 'db-client', re: /new\s+(?:Pool|Client|PrismaClient|MongoClient|Redis|DynamoDBClient|SqlConnection|NpgsqlConnection|MySqlConnection)\(|sql\.Open\(|pgx(?:pool)?\.(?:Connect|New)|mongoose\.connect\(|DbContext\b|UseSqlServer\(|UseNpgsql\(|createConnection\(|redis\.NewClient\(|drizzle\(/g },
  { kind: 'queue', re: /SendMessage(?:Async|Batch)?\(|\.publish\(|producer\.send\(|\.sendMessage\(|PublishAsync\(|\.Produce\(|env\.[A-Z_]+\.send\(|SendAsync\(\s*new\s+ServiceBusMessage/g },
  { kind: 'cloud-sdk', re: /new\s+\w+Client\(\s*\{|boto3\.(?:client|resource)\(|Amazon\w+Client\(|new\s+(?:BlobServiceClient|SecretClient|ServiceBusClient)\(|storage\.NewClient\(/g },
  { kind: 'email-sms', re: /sendMail\(|SendEmail(?:Async)?\(|ses\.send|sgMail\.send|twilio|nodemailer|SmtpClient/g },
  { kind: 'llm', re: /anthropic|openai|ChatCompletion|messages\.create\(|bedrock|generateText\(|streamText\(/gi },
];

export const CONFIG = [
  { re: /process\.env\.(?<name>[A-Za-z_][A-Za-z0-9_]*)|process\.env\[\s*['"](?<name2>[^'"]+)/g },
  { re: /Environment\.GetEnvironmentVariable\(\s*"(?<name>[^"]+)"|(?:[Cc]onfiguration|config)\[\s*"(?<name2>[^"]+)"\]|GetConnectionString\(\s*"(?<name3>[^"]+)"/g },
  { re: /os\.(?:Getenv|LookupEnv)\(\s*"(?<name>[^"]+)"/g },
  { re: /os\.environ(?:\.get)?\(?\[?\s*['"](?<name>[^'"]+)|os\.getenv\(\s*['"](?<name2>[^'"]+)/g },
  { re: /\benv\.(?<name>[A-Z][A-Z0-9_]{2,})\b/g },
  { re: /System\.getenv\(\s*"(?<name>[^"]+)"|@Value\(\s*"\$\{(?<name2>[^}:]+)/g },
];

// Dangerous sinks and risky settings. Each needs a human-style read before it becomes a finding.
export const SINKS = [
  { check: 'T-INJECTION', what: 'SQL built from strings', re: /(?:SELECT|INSERT|UPDATE|DELETE)[^;\n]{0,120}(?:['"`]\s*\+\s*\w|\$\{|\{0\}|%s|%v|fmt\.Sprintf\(\s*"(?:SELECT|INSERT|UPDATE|DELETE))|FromSqlRaw\(\s*\$?"|ExecuteSqlRaw\(\s*\$"|\.raw\(\s*`|\$queryRawUnsafe\(|\.query\(\s*`[^`]*\$\{/gi },
  { check: 'T-INJECTION', what: 'command execution', re: /child_process|\bexecSync\(|\bspawn\(|exec\.Command\(|Process\.Start\(|subprocess\.(?:run|call|Popen)\([^)]*shell\s*=\s*True|os\.system\(|Runtime\.getRuntime\(\)\.exec/g },
  { check: 'T-INJECTION', what: 'dynamic code evaluation', re: /\beval\(|new\s+Function\(|vm\.runIn|pickle\.loads?\(|yaml\.load\((?![^)]*SafeLoader)|BinaryFormatter|TypeNameHandling\.(?:All|Auto|Objects)|ObjectInputStream|Marshal\.load/g },
  { check: 'E-SSRF-META', what: 'outbound URL built from input', re: /(?<![.\w])fetch\(\s*(?:req\.|request\.url|ctx\.|c\.req|body|params|query|url\b)|(?<![.\w])fetch\(\s*`[^`]*\$\{|http\.Get\(\s*(?:r\.|req\.|url)|HttpClient\S*\.GetAsync\(\s*(?:\$"|\w+\s*\+)|requests\.get\(\s*(?:request|url|f['"])/g },
  { check: 'BFF-REDIRECT', what: 'redirect to a request value', re: /res\.redirect\(\s*(?:req|request)\.|Redirect\(\s*(?:returnUrl|redirectUrl|url|next)\b|http\.Redirect\([^,]+,\s*[^,]+,\s*r\.|Response\.redirect\(\s*(?:url|new URL\()|redirect\(\s*request\.(?:args|GET)/g },
  { check: 'T-INJECTION', what: 'file path from input', re: /(?:readFile|createReadStream|sendFile|File\.(?:ReadAll\w+|Open\w*)|os\.Open|open)\(\s*(?:path\.join\()?[^)]*(?:req\.|request\.|params|query|body)/g },
  { check: 'I-EXPOSURE', what: 'raw HTML sink', re: /dangerouslySetInnerHTML|\.innerHTML\s*=|v-html=|Html\.Raw\(|\|\s*safe\b|template\.HTML\(/g },
  { check: 'I-CORS', what: 'CORS wildcard or reflected origin', re: /Access-Control-Allow-Origin['"]?\s*[,:]\s*['"]\*|AllowAnyOrigin\(\)|origin:\s*(?:true|['"]\*['"])|SetIsOriginAllowed\(\s*_\s*=>\s*true|AllowedOrigins:\s*\[\s*"\*"/g },
  { check: 'I-ERRORS', what: 'error details returned to the client', re: /(?:res\.(?:status\(\d+\)\.)?(?:send|json)|return\s+new\s+Response|c\.(?:JSON|String))\([^)]*(?:err|error|e)\.(?:stack|message)|UseDeveloperExceptionPage\(|DEBUG\s*=\s*True|app\.debug\s*=\s*True|gin\.SetMode\(gin\.DebugMode\)/g },
  { check: 'I-LOGGING', what: 'headers, bodies or tokens logged', re: /(?:console\.\w+|\blog(?:ger)?\.\w+|_logger\.Log\w*|log\.Printf?|logging\.\w+)\([^)]*(?:\bheaders\b|\bauthorization\b|\bcookies?\b|\b(?:access|refresh|id|session)?[Tt]oken\b|\bpassword\b|\bsecret\b|req\.body|request\.body|JSON\.stringify\(\s*event\s*\)|\(\s*event\s*\))/gi },
  { check: 'S-TOKEN', what: 'weak token or secret handling', re: /Math\.random\(\)|algorithms:\s*\[\s*['"]none|ValidateLifetime\s*=\s*false|ValidateIssuer\s*=\s*false|ValidateAudience\s*=\s*false|RequireHttpsMetadata\s*=\s*false|InsecureSkipVerify:\s*true|rejectUnauthorized:\s*false|verify\s*=\s*False/g },
  { check: 'D-RESOURCE', what: 'server without timeouts or limits', re: /http\.ListenAndServe\(|&http\.Server\{(?![^}]*Timeout)|MaxRequestBodySize\s*=\s*null|limit:\s*['"]\d{3,}mb/g },
  { check: 'X-OTHER', what: 'debug or admin surface', re: /\/debug\/pprof|net\/http\/pprof|UseSwaggerUI\(|swagger-ui|\/actuator|management\.endpoints\.web\.exposure\.include\s*=\s*\*|graphiql:\s*true|introspection:\s*true/g },
];

// Dependency names that reveal frameworks and external systems. Matched against manifest dependency names.
export const DEPENDENCIES = [
  [/^(express|koa|@koa\/router|fastify|hono|itty-router|elysia|restify|@hapi\/hapi|polka)$/, 'web framework'],
  [/^(@nestjs\/core|next|nuxt|@remix-run\/\w+|@sveltejs\/kit|astro)$/, 'web framework'],
  [/^(wrangler|@cloudflare\/workers-types|@cloudflare\/\w+)$/, 'cloudflare workers'],
  [/^(aws-cdk-lib|serverless|@aws-sdk\/.+|aws-sdk)$/, 'aws'],
  [/^(@apollo\/server|apollo-server.*|graphql-yoga|graphql|type-graphql|@nestjs\/graphql)$/, 'graphql'],
  [/^(socket\.io|ws|@fastify\/websocket)$/, 'websocket'],
  [/^(prisma|@prisma\/client|typeorm|sequelize|drizzle-orm|mongoose|pg|mysql2|mongodb|ioredis|redis|knex|kysely|better-sqlite3)$/, 'database'],
  [/^(jsonwebtoken|jose|passport.*|next-auth|@auth\/.+|express-session|@clerk\/.+|oidc-client.*|openid-client|lucia)$/, 'auth'],
  [/^(axios|got|node-fetch|undici|ky|superagent)$/, 'http client'],
  [/^(stripe|@stripe\/.+|@mollie\/.+|square|braintree|@paypal\/.+)$/, 'payments'],
  [/^(openai|@anthropic-ai\/sdk|@ai-sdk\/.+|ai|langchain|@langchain\/.+)$/, 'llm'],
  [/^(helmet|cors|csurf|express-rate-limit|rate-limiter-flexible)$/, 'security middleware'],
  [/^Microsoft\.AspNetCore\.(?!.*Test)/, 'aspnet core'],
  [/^Microsoft\.AspNetCore\.Authentication\.|^Microsoft\.Identity\.Web|^Duende\.|^IdentityServer4/, 'auth'],
  [/^(Microsoft\.EntityFrameworkCore.*|Dapper|Npgsql.*|MySqlConnector|MongoDB\.Driver|StackExchange\.Redis)$/, 'database'],
  [/^(MassTransit.*|Azure\.Messaging\..+|RabbitMQ\.Client|Confluent\.Kafka|AWSSDK\.SQS)$/, 'messaging'],
  [/^(Grpc\.AspNetCore|Grpc\.Net\.Client|HotChocolate.*|GraphQL\.Server.*)$/, 'rpc/graphql'],
  [/^(Azure\..+|AWSSDK\..+|Google\.Cloud\..+)$/, 'cloud sdk'],
  [/^(Swashbuckle.*|NSwag.*|Microsoft\.AspNetCore\.OpenApi)$/, 'openapi'],
  [/^github\.com\/(gin-gonic\/gin|go-chi\/chi.*|labstack\/echo.*|gofiber\/fiber.*|gorilla\/mux|julienschmidt\/httprouter)/, 'web framework'],
  [/^(google\.golang\.org\/grpc|github\.com\/99designs\/gqlgen|github\.com\/graphql-go\/graphql)/, 'rpc/graphql'],
  [/^github\.com\/(jackc\/pgx.*|lib\/pq|go-sql-driver\/mysql|redis\/go-redis.*|go-gorm\/gorm|jmoiron\/sqlx)|^gorm\.io\/|^go\.mongodb\.org/, 'database'],
  [/^github\.com\/(golang-jwt\/jwt.*|coreos\/go-oidc.*|lestrrat-go\/jwx.*)|^golang\.org\/x\/oauth2/, 'auth'],
  [/^github\.com\/aws\/aws-sdk-go.*|^cloud\.google\.com\/go|^github\.com\/Azure\/azure-sdk-for-go/, 'cloud sdk'],
  [/^github\.com\/(segmentio\/kafka-go|confluentinc\/.+|rabbitmq\/amqp091-go|nats-io\/.+)/, 'messaging'],
  [/^(fastapi|flask|django|starlette|sanic|aiohttp|tornado|litestar)$/i, 'web framework'],
  [/^(sqlalchemy|psycopg2?.*|pymongo|redis|asyncpg|django-.*orm)$/i, 'database'],
  [/^(pyjwt|python-jose|authlib|django-allauth|flask-login)$/i, 'auth'],
  [/^(boto3|google-cloud-.+|azure-.+)$/i, 'cloud sdk'],
  [/^(requests|httpx|aiohttp)$/i, 'http client'],
  [/^(celery|kombu|pika|kafka-python|confluent-kafka)$/i, 'messaging'],
  [/spring-boot-starter-(web|webflux)|spring-boot-starter-security|spring-security/, 'web framework'],
  [/^(rails|sinatra|grape|devise|jwt)$/, 'web framework'],
  [/^(laravel\/framework|symfony\/.+|slim\/slim)$/, 'web framework'],
  [/^(axum|actix-web|rocket|warp|tonic|jsonwebtoken|sqlx|diesel)$/, 'web framework'],
];
