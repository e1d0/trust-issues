#!/usr/bin/env node
// Deterministic entry-point inventory for AWS CDK stacks written in TypeScript.
// - API routes from RestApi / LambdaRestApi / SpecRestApi (addResource, resourceForPath, addProxy, addMethod),
//   HttpApi (addRoutes, HttpRoute) and WebSocketApi (route options, addRoute), with auth, API key, request model and integration
// - Lambda function URLs, event sources, schedules and rules, stores, IAM, secrets, edge and identity resources
// - flags for risky settings (wildcard IAM, FullAccess policies, public function URLs, public buckets, CORS with credentials)
// Constructs are matched by class name, so any import alias works (apigw.RestApi, RestApi, ...).
// Usage: node extract-entry-points.mjs <stack.ts> [more.ts ...] [--match <text>] [--json] [--out <file>]
//   --match keeps only routes and resources whose text contains <text> (case-insensitive). Repeat it or pass a comma list.
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';

const load = (name) => {
  for (const base of [import.meta.url, path.join(process.cwd(), 'package.json')]) {
    try {
      return createRequire(base)(name);
    } catch {}
  }
  console.error(`${name} not found. Run npm install in the skill folder, or run from a repo that has it.`);
  process.exit(2);
};
const ts = load('typescript');

const args = process.argv.slice(2);
const asJson = args.includes('--json');
const outIdx = args.indexOf('--out');
const outFile = outIdx >= 0 ? args[outIdx + 1] : undefined;
const matches = args.flatMap((a, i) => (a === '--match' ? args[i + 1].split(',') : [])).map((m) => m.trim().toLowerCase()).filter(Boolean);
const match = matches.length ? matches.join(',') : undefined;
const files = args.filter((a, i) => !a.startsWith('--') && args[i - 1] !== '--out' && args[i - 1] !== '--match');
if (!files.length) {
  console.error('usage: extract-entry-points.mjs <stack.ts> [more.ts ...] [--match text] [--json] [--out file]');
  process.exit(2);
}

const REST_APIS = ['RestApi', 'LambdaRestApi', 'SpecRestApi', 'StepFunctionsRestApi'];
const HTTP_APIS = ['HttpApi'];
const WS_APIS = ['WebSocketApi'];
const AUTHORIZERS = {
  RequestAuthorizer: 'lambda-authorizer', TokenAuthorizer: 'lambda-authorizer', CognitoUserPoolsAuthorizer: 'cognito',
  HttpLambdaAuthorizer: 'lambda-authorizer', HttpUserPoolAuthorizer: 'cognito', HttpJwtAuthorizer: 'jwt', HttpIamAuthorizer: 'iam',
  HttpNoneAuthorizer: 'none', WebSocketLambdaAuthorizer: 'lambda-authorizer', WebSocketIamAuthorizer: 'iam',
};
const AUTH_TYPES = { IAM: 'iam', COGNITO: 'cognito', CUSTOM: 'lambda-authorizer', NONE: 'none' };
const INTEGRATIONS = {
  LambdaIntegration: 'lambda', HttpLambdaIntegration: 'lambda', WebSocketLambdaIntegration: 'lambda', HttpIntegration: 'http',
  HttpUrlIntegration: 'http', MockIntegration: 'mock', StepFunctionsIntegration: 'stepfunctions', SqsSendMessageIntegration: 'sqs',
  HttpSqsIntegration: 'sqs', HttpStepFunctionsIntegration: 'stepfunctions', HttpAlbIntegration: 'alb', HttpNlbIntegration: 'nlb',
  WebSocketAwsIntegration: 'aws', WebSocketMockIntegration: 'mock',
};
const RESOURCES = {
  Function: 'compute:lambda', NodejsFunction: 'compute:lambda', PythonFunction: 'compute:lambda', GoFunction: 'compute:lambda',
  DockerImageFunction: 'compute:lambda', SingletonFunction: 'compute:lambda', StateMachine: 'compute:stepfunctions',
  FargateService: 'compute:ecs', ApplicationLoadBalancedFargateService: 'entry:alb', ApplicationLoadBalancer: 'entry:alb',
  SqsEventSource: 'trigger:queue', DynamoEventSource: 'trigger:dynamodb-stream', KinesisEventSource: 'trigger:kinesis',
  S3EventSource: 'trigger:s3', SnsEventSource: 'trigger:sns', ManagedKafkaEventSource: 'trigger:kafka', LambdaSubscription: 'trigger:sns',
  Rule: 'trigger:event-rule', CfnSchedule: 'trigger:schedule', Schedule: 'trigger:schedule', CfnPipe: 'trigger:pipe', Pipe: 'trigger:pipe',
  Queue: 'store:sqs', Table: 'store:dynamodb', TableV2: 'store:dynamodb', Bucket: 'store:s3', DatabaseInstance: 'store:rds',
  DatabaseCluster: 'store:rds', ServerlessCluster: 'store:rds', CfnCacheCluster: 'store:elasticache', Topic: 'channel:sns',
  EventBus: 'channel:eventbridge', GraphqlApi: 'entry:appsync', Distribution: 'entry:cloudfront', CloudFrontWebDistribution: 'entry:cloudfront',
  CfnWebACL: 'edge:waf', CfnWebACLAssociation: 'edge:waf', UserPool: 'identity:cognito', UserPoolClient: 'identity:cognito-client',
  CfnIdentityPool: 'identity:cognito-identity-pool', Role: 'privilege:role', PolicyStatement: 'privilege:statement', User: 'privilege:iam-user',
  AccessKey: 'privilege:access-key', Secret: 'secret:secretsmanager', StringParameter: 'secret:ssm', Key: 'secret:kms',
};
const KEEP = ['functionName', 'entry', 'handler', 'queueName', 'tableName', 'bucketName', 'topicName', 'eventBusName', 'ruleName', 'schedule',
  'eventPattern', 'targets', 'actions', 'resources', 'principals', 'assumedBy', 'managedPolicies', 'authType', 'publicReadAccess',
  'deadLetterQueue', 'batchSize', 'reportBatchItemFailures', 'encryption', 'removalPolicy', 'name', 'authorizationConfig', 'secretName'];

const apis = [];
const resources = [];
const warnings = [];

for (const file of files) {
  const src = fs.readFileSync(file, 'utf8');
  const sf = ts.createSourceFile(file, src, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  const lineOf = (n) => sf.getLineAndCharacterOfPosition(n.getStart(sf)).line + 1;
  const text = (n) => n.getText(sf).replace(/\s+/g, ' ');
  const where = (n) => `${files.length > 1 ? `${path.basename(file)}:` : 'line '}${lineOf(n)}`;
  const warn = (n, msg) => warnings.push(`${where(n)}: ${msg}`);

  const props = (obj) => {
    const out = {};
    if (!obj || !ts.isObjectLiteralExpression(obj)) return out;
    for (const p of obj.properties) {
      if (ts.isPropertyAssignment(p)) out[p.name.getText(sf)] = p.initializer;
      else if (ts.isShorthandPropertyAssignment(p)) out[p.name.getText(sf)] = p.name;
      else if (ts.isSpreadAssignment(p)) out['...'] = p.expression;
    }
    return out;
  };
  const literal = (n) => {
    if (!n) return undefined;
    if (ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n)) return n.text;
    if (ts.isTemplateExpression(n)) return n.head.text + n.templateSpans.map((s) => '${' + s.expression.getText(sf) + '}' + s.literal.text).join('');
    if (ts.isNumericLiteral(n)) return Number(n.text);
    if (n.kind === ts.SyntaxKind.TrueKeyword) return true;
    if (n.kind === ts.SyntaxKind.FalseKeyword) return false;
    return text(n);
  };
  const optionsOf = (n) => [...(n.arguments ?? [])].reverse().find((a) => ts.isObjectLiteralExpression(a));
  const isLiteral = (n) => n && (ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n));
  const className = (n) => (ts.isNewExpression(n) ? (ts.isPropertyAccessExpression(n.expression) ? n.expression.name.text : n.expression.getText(sf)) : undefined);
  const lastName = (n) => (ts.isPropertyAccessExpression(n) ? n.name.text : n.getText(sf));
  const unwrap = (n) => {
    while (n && (ts.isAsExpression(n) || ts.isParenthesizedExpression(n) || ts.isNonNullExpression(n) || ts.isSatisfiesExpression?.(n))) n = n.expression;
    return n;
  };

  // Variable and this.x assignments, so references can be followed back to the construct that made them.
  const decls = new Map();
  const collect = (node) => {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) decls.set(node.name.text, node.initializer);
    if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken) decls.set(node.left.getText(sf), node.right);
    if (ts.isPropertyDeclaration(node) && node.initializer) decls.set(`this.${node.name.getText(sf)}`, node.initializer);
    ts.forEachChild(node, collect);
  };
  collect(sf);
  const resolve = (n, depth = 0) => {
    n = unwrap(n);
    if (!n || depth > 12) return n;
    if (ts.isIdentifier(n) || (ts.isPropertyAccessExpression(n) && n.expression.kind === ts.SyntaxKind.ThisKeyword)) {
      const d = decls.get(n.getText(sf));
      return d ? resolve(d, depth + 1) : n;
    }
    return n;
  };

  const lambdaName = (n) => {
    const r = resolve(n);
    if (r && ts.isNewExpression(r) && RESOURCES[className(r)] === 'compute:lambda') {
      const p = props(r.arguments?.[2]);
      return literal(p.functionName) ?? literal(r.arguments?.[1]);
    }
    return undefined;
  };

  const classifyAuth = (authorizerNode, authTypeNode) => {
    if (authorizerNode) {
      const r = resolve(authorizerNode);
      const kind = r && ts.isNewExpression(r) ? AUTHORIZERS[className(r)] : undefined;
      const ref = text(authorizerNode);
      if (kind) return { type: kind, ref };
      if (authTypeNode) return { type: AUTH_TYPES[lastName(authTypeNode)] ?? 'authorizer', ref };
      return { type: 'authorizer', ref };
    }
    if (authTypeNode) return { type: AUTH_TYPES[lastName(authTypeNode)] ?? 'authorizer', ref: text(authTypeNode) };
    return undefined;
  };

  const classifyIntegration = (n) => {
    if (!n) return { type: 'none', ref: null };
    const r = resolve(n);
    const cls = r && ts.isNewExpression(r) ? className(r) : undefined;
    if (cls === 'AwsIntegration') return { type: literal(props(r.arguments?.[0]).service) ?? 'aws', ref: text(n).slice(0, 80) };
    if (cls && INTEGRATIONS[cls]) {
      const fnArg = r.arguments?.find((a) => lambdaName(a) || ts.isIdentifier(a) || ts.isPropertyAccessExpression(a));
      const type = INTEGRATIONS[cls];
      return { type, ref: fnArg ? text(fnArg) : text(n).slice(0, 80), lambdaName: type === 'lambda' && fnArg ? lambdaName(fnArg) : undefined };
    }
    return { type: 'other', ref: text(n).slice(0, 80) };
  };

  const inLoop = (n) => {
    for (let p = n.parent; p; p = p.parent) {
      if (ts.isForStatement(p) || ts.isForOfStatement(p) || ts.isForInStatement(p) || ts.isWhileStatement(p)) return true;
      if ((ts.isArrowFunction(p) || ts.isFunctionExpression(p)) && ts.isCallExpression(p.parent) && ts.isPropertyAccessExpression(p.parent.expression) && ['forEach', 'map', 'flatMap'].includes(p.parent.expression.name.text)) return true;
    }
    return false;
  };

  const joinPath = (base, seg) => `${base.replace(/\/+$/, '')}/${String(seg).replace(/^\/+/, '')}`;
  const apiByNode = new Map();
  const apiFor = (newExpr, kind) => {
    if (apiByNode.has(newExpr)) return apiByNode.get(newExpr);
    const p = props(newExpr.arguments?.[2]);
    const api = { construct: className(newExpr), file, line: lineOf(newExpr), kind, id: literal(newExpr.arguments?.[1]), settings: {}, routes: [], defaults: {} };
    const dmo = props(p.defaultMethodOptions);
    api.defaults = { authorizer: dmo.authorizer ?? p.defaultAuthorizer, authType: dmo.authorizationType, apiKeyRequired: literal(dmo.apiKeyRequired) === true };
    const cors = p.defaultCorsPreflightOptions ?? p.corsPreflight;
    if (cors) {
      api.settings.cors = text(cors).slice(0, 300);
      const c = props(cors);
      const all = c.allowOrigins && /ALL_ORIGINS|['"]\*['"]/.test(text(c.allowOrigins));
      if (all && literal(c.allowCredentials) === true) api.settings.flag = 'CORS allows all origins with credentials';
      else if (all) api.settings.corsAllOrigins = true;
    }
    if (p.policy) api.settings.policy = text(p.policy).slice(0, 200);
    if (p.deployOptions) api.settings.deployOptions = text(p.deployOptions).slice(0, 200);
    if (p.endpointTypes || p.endpointConfiguration) api.settings.endpoint = text(p.endpointTypes ?? p.endpointConfiguration).slice(0, 80);
    if (p.disableExecuteApiEndpoint) api.settings.disableExecuteApiEndpoint = literal(p.disableExecuteApiEndpoint);
    apis.push(api);
    apiByNode.set(newExpr, api);
    return api;
  };

  // Follows a resource expression (api.root.addResource('a').addResource('{id}'), a variable, resourceForPath) to its API and path.
  const resourcePath = (n, depth = 0) => {
    n = resolve(n);
    if (!n || depth > 20) return undefined;
    if (ts.isNewExpression(n) && REST_APIS.includes(className(n))) return { api: apiFor(n, 'REST'), path: '/' };
    if (ts.isPropertyAccessExpression(n) && n.name.text === 'root') return resourcePath(n.expression, depth + 1);
    if (ts.isCallExpression(n) && ts.isPropertyAccessExpression(n.expression)) {
      const m = n.expression.name.text;
      const base = resourcePath(n.expression.expression, depth + 1);
      if (!base) return undefined;
      if (m === 'addResource' || m === 'resourceForPath' || m === 'getResource') {
        const arg = n.arguments[0];
        const dynamic = !isLiteral(arg) && !ts.isTemplateExpression(arg);
        if (dynamic) warn(n, `non-literal resource path (${text(arg).slice(0, 60)}); read manually`);
        return { api: base.api, path: joinPath(base.path, dynamic ? '${' + text(arg) + '}' : literal(arg)) };
      }
      if (m === 'addProxy') return { api: base.api, path: joinPath(base.path, '{proxy+}') };
    }
    return undefined;
  };

  const pushRoute = (api, node, route) => {
    const auth = route.auth ?? classifyAuth(api.defaults.authorizer, api.defaults.authType) ?? { type: 'none', ref: null };
    api.routes.push({
      line: lineOf(node),
      method: route.method,
      path: route.path,
      auth: auth.type,
      authRef: auth.ref,
      apiKeyRequired: route.apiKeyRequired ?? api.defaults.apiKeyRequired ?? false,
      hasModel: Boolean(route.hasModel),
      hasValidator: Boolean(route.hasValidator),
      proxy: Boolean(route.proxy),
      integration: route.integration.type,
      integrationRef: route.integration.ref,
      lambdaName: route.integration.lambdaName,
      inLoop: inLoop(node) || undefined,
    });
    if (inLoop(node)) warn(node, `route ${route.method} ${route.path} is created in a loop; the real set of routes may differ, read manually`);
  };

  const summarize = (arg) => {
    if (!arg) return '';
    if (!ts.isObjectLiteralExpression(arg)) return text(arg).slice(0, 80);
    const p = props(arg);
    return KEEP.filter((k) => p[k]).map((k) => `${k}=${text(p[k]).slice(0, 120)}`).join('; ');
  };
  const flagsFor = (cls, p, node) => {
    const flags = [];
    const t = (k) => (p[k] ? text(p[k]) : '');
    if (cls === 'PolicyStatement' && (/['"]\*['"]/.test(t('actions')) || /['"][a-z0-9-]+:\*['"]/.test(t('actions')))) flags.push('wildcard actions');
    if (cls === 'PolicyStatement' && /['"]\*['"]/.test(t('resources'))) flags.push('wildcard resources');
    if (/FullAccess|AdministratorAccess/.test(t('managedPolicies'))) flags.push('broad managed policy');
    if (cls === 'Bucket' && literal(p.publicReadAccess) === true) flags.push('public read access');
    if (cls === 'Queue' && !p.deadLetterQueue) flags.push('no dead-letter queue');
    if (cls === 'SqsEventSource' && literal(p.reportBatchItemFailures) !== true) flags.push('no partial batch failure reporting');
    if (RESOURCES[cls] === 'compute:lambda' && p.environment && /secret|password|token|apikey|api_key|private/i.test(t('environment'))) flags.push('secret-like names in plain environment variables');
    if (cls === 'GraphqlApi' && /API_KEY/.test(t('authorizationConfig'))) flags.push('API key auth mode');
    return flags;
  };

  const visit = (node) => {
    if (ts.isNewExpression(node)) {
      const cls = className(node);
      const p = props(optionsOf(node));
      if (REST_APIS.includes(cls)) {
        const api = apiFor(node, 'REST');
        if (cls === 'LambdaRestApi' && literal(p.proxy) !== false) {
          const integration = { type: 'lambda', ref: p.handler ? text(p.handler) : null, lambdaName: p.handler ? lambdaName(p.handler) : undefined };
          pushRoute(api, node, { method: 'ANY', path: '/', integration, proxy: true });
          pushRoute(api, node, { method: 'ANY', path: '/{proxy+}', integration, proxy: true });
        }
        if (cls === 'SpecRestApi') warn(node, 'SpecRestApi: routes come from the OpenAPI definition; run spec-drift against it and read it by hand');
      } else if (HTTP_APIS.includes(cls)) {
        apiFor(node, 'HTTP');
      } else if (WS_APIS.includes(cls)) {
        const api = apiFor(node, 'WEBSOCKET');
        for (const [key, route] of [['connectRouteOptions', '$connect'], ['disconnectRouteOptions', '$disconnect'], ['defaultRouteOptions', '$default']]) {
          if (!p[key]) continue;
          const rp = props(p[key]);
          pushRoute(api, node, { method: 'WS', path: route, auth: classifyAuth(rp.authorizer) ?? { type: 'none', ref: null }, integration: classifyIntegration(rp.integration) });
        }
      } else if (cls === 'HttpRoute') {
        const apiNode = p.httpApi ? resolve(p.httpApi) : undefined;
        const api = apiNode && ts.isNewExpression(apiNode) && HTTP_APIS.includes(className(apiNode)) ? apiFor(apiNode, 'HTTP') : undefined;
        const key = text(p.routeKey ?? node);
        if (api) pushRoute(api, node, { method: key.match(/HttpMethod\.(\w+)/)?.[1] ?? 'ANY', path: literal(props(p.routeKey).path) ?? key, auth: classifyAuth(p.authorizer), integration: classifyIntegration(p.integration) });
        else warn(node, 'HttpRoute on an API that could not be resolved; read manually');
      } else if (RESOURCES[cls]) {
        const decl = ts.isVariableDeclaration(node.parent) ? node.parent.name.getText(sf) : ts.isBinaryExpression(node.parent) ? node.parent.left.getText(sf) : undefined;
        let kind = RESOURCES[cls];
        if (cls === 'Rule' && p.schedule) kind = 'trigger:schedule';
        const flags = flagsFor(cls, p, node);
        resources.push({ file, line: lineOf(node), kind, construct: cls, id: isLiteral(node.arguments?.[1]) ? node.arguments[1].text : undefined, variable: decl, summary: summarize(optionsOf(node) ?? node.arguments?.[0]), flags: flags.length ? flags : undefined });
      }
    }

    if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
      const m = node.expression.name.text;
      const target = node.expression.expression;
      if (m === 'addMethod') {
        const res = resourcePath(target);
        if (!res) warn(node, `addMethod on a resource that could not be resolved (${text(target).slice(0, 60)}); read manually`);
        else {
          const o = props(node.arguments[2]);
          const integration = classifyIntegration(node.arguments[1]);
          const proxyFlag = ts.isNewExpression(resolve(node.arguments[1]) ?? node) ? literal(props(resolve(node.arguments[1]).arguments?.[1]).proxy) : undefined;
          pushRoute(res.api, node, {
            method: literal(node.arguments[0]),
            path: res.path,
            auth: classifyAuth(o.authorizer, o.authorizationType),
            apiKeyRequired: o.apiKeyRequired ? literal(o.apiKeyRequired) === true : undefined,
            hasModel: Boolean(o.requestModels),
            hasValidator: Boolean(o.requestValidator || o.requestValidatorOptions),
            proxy: integration.type === 'lambda' && proxyFlag !== false,
            integration,
          });
          if (o['...']) warn(node, `addMethod options use a spread (${text(o['...']).slice(0, 60)}); auth or model may come from it, read manually`);
        }
      } else if (m === 'addProxy') {
        const res = resourcePath(target);
        const o = props(node.arguments[0]);
        if (res && literal(o.anyMethod) !== false) {
          const dmo = props(o.defaultMethodOptions);
          pushRoute(res.api, node, { method: 'ANY', path: joinPath(res.path, '{proxy+}'), auth: classifyAuth(dmo.authorizer, dmo.authorizationType), apiKeyRequired: dmo.apiKeyRequired ? literal(dmo.apiKeyRequired) === true : undefined, integration: classifyIntegration(o.defaultIntegration), proxy: true });
        }
      } else if (m === 'addRoutes') {
        const apiNode = resolve(target);
        const api = apiNode && ts.isNewExpression(apiNode) && HTTP_APIS.includes(className(apiNode)) ? apiFor(apiNode, 'HTTP') : undefined;
        const o = props(node.arguments[0]);
        if (!api) warn(node, `addRoutes on an API that could not be resolved (${text(target).slice(0, 60)}); read manually`);
        else {
          const methods = o.methods && ts.isArrayLiteralExpression(o.methods) ? o.methods.elements.map((e) => lastName(e)) : ['ANY'];
          if (o.methods && !ts.isArrayLiteralExpression(o.methods)) warn(node, `addRoutes methods are not a literal list (${text(o.methods).slice(0, 60)}); read manually`);
          for (const method of methods) pushRoute(api, node, { method, path: literal(o.path), auth: classifyAuth(o.authorizer), integration: classifyIntegration(o.integration) });
        }
      } else if (m === 'addRoute') {
        const apiNode = resolve(target);
        if (apiNode && ts.isNewExpression(apiNode) && WS_APIS.includes(className(apiNode))) {
          const o = props(node.arguments[1]);
          pushRoute(apiFor(apiNode, 'WEBSOCKET'), node, { method: 'WS', path: literal(node.arguments[0]), auth: classifyAuth(o.authorizer) ?? { type: 'none', ref: null }, integration: classifyIntegration(o.integration) });
        }
      } else if (m === 'addFunctionUrl') {
        const o = props(node.arguments[0]);
        const none = !o.authType || /NONE/.test(text(o.authType));
        resources.push({ file, line: lineOf(node), kind: 'entry:function-url', construct: 'FunctionUrl', variable: text(target), lambdaName: lambdaName(target), summary: summarize(node.arguments[0]) || 'authType defaults to AWS_IAM', flags: none && o.authType ? ['public function URL (authType NONE)'] : undefined });
      } else if (['addEventSource', 'addEventNotification', 'addSubscription', 'addTarget', 'addToRolePolicy', 'addToPolicy', 'addToResourcePolicy'].includes(m) || /^grant/.test(m)) {
        const kind = m === 'addEventSource' ? 'trigger:event-source' : m === 'addEventNotification' ? 'trigger:s3' : m === 'addSubscription' ? 'trigger:sns' : m === 'addTarget' ? 'trigger:rule-target' : /^grant/.test(m) ? 'privilege:grant' : 'privilege:statement';
        resources.push({ file, line: lineOf(node), kind, construct: m, variable: text(target).slice(0, 60), summary: node.arguments.map((a) => text(a).slice(0, 100)).join(', ') });
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
}

const hit = (o) => !matches.length || matches.some((m) => JSON.stringify(o).toLowerCase().includes(m));
for (const a of apis) {
  a.routes = a.routes.filter(hit);
  delete a.defaults;
}
const keptApis = matches.length ? apis.filter((a) => a.routes.length) : apis;
const keptResources = resources.filter(hit);
const all = keptApis.flatMap((a) => a.routes);
const summary = {
  files,
  apis: keptApis.length,
  routes: all.length,
  byAuth: all.reduce((acc, r) => ((acc[r.auth] = (acc[r.auth] ?? 0) + 1), acc), {}),
  unauthenticated: all.filter((r) => r.auth === 'none' && !r.apiKeyRequired).length,
  apiKeyOnly: all.filter((r) => r.auth === 'none' && r.apiKeyRequired).length,
  mutatingWithoutModel: all.filter((r) => ['POST', 'PUT', 'PATCH'].includes(r.method) && !r.hasModel).length,
  proxyRoutes: all.filter((r) => /\{proxy\+\}/.test(String(r.path)) || r.method === 'ANY').length,
  flagged: keptResources.filter((r) => r.flags).length + keptApis.filter((a) => a.settings.flag).length,
  match: match ?? null,
  resourcesByKind: keptResources.reduce((acc, r) => ((acc[r.kind] = (acc[r.kind] ?? 0) + 1), acc), {}),
};
const result = { summary, apis: keptApis, resources: keptResources, warnings };

let output;
if (asJson) output = JSON.stringify(result, null, 2);
else {
  const cell = (s) => String(s ?? '').replace(/\|/g, '\\|');
  const lines = [`# Entry points: ${files.map((f) => path.basename(f)).join(', ')}${match ? ` (match: ${match})` : ''}`, '', '```json', JSON.stringify(summary, null, 2), '```', ''];
  for (const a of keptApis) {
    lines.push(`## ${a.kind} API ${a.id ?? ''} (${a.construct} at ${path.basename(a.file)}:${a.line})`, '');
    if (Object.keys(a.settings).length) lines.push('Settings: `' + JSON.stringify(a.settings) + '`', '');
    lines.push('| Line | Method | Path | Auth | API key | Model | Integration |', '|---|---|---|---|---|---|---|');
    for (const r of a.routes) lines.push(`| ${r.line} | ${r.method} | \`${r.path}\` | ${r.auth}${r.authRef ? ` (${cell(r.authRef)})` : ''} | ${r.apiKeyRequired ? 'yes' : ''} | ${r.hasModel ? 'yes' : r.hasValidator ? 'validator only' : ''} | ${r.integration}${r.lambdaName ? ` (${r.lambdaName})` : r.integrationRef ? ` (${cell(r.integrationRef)})` : ''} |`);
    lines.push('');
  }
  if (keptResources.length) {
    lines.push('## Other entry points and resources', '', '| File:line | Kind | Construct | Summary | Flags |', '|---|---|---|---|---|');
    for (const r of keptResources) lines.push(`| ${path.basename(r.file)}:${r.line} | ${r.kind} | ${r.construct}${r.id ? ` \`${r.id}\`` : ''} | ${cell(r.summary)} | ${(r.flags ?? []).join(', ')} |`);
    lines.push('');
  }
  if (warnings.length) lines.push('## Warnings (read these parts by hand)', '', ...warnings.map((w) => `- ${w}`), '');
  output = lines.join('\n');
}
if (outFile) {
  fs.mkdirSync(path.dirname(outFile), { recursive: true });
  fs.writeFileSync(outFile, output);
  console.log(`wrote ${outFile}`);
} else console.log(output);
