// @ts-nocheck
// Fixture for extract-entry-points tests. Not real infrastructure.
import * as apigw from 'aws-cdk-lib/aws-apigateway';
import { HttpApi, HttpMethod } from 'aws-cdk-lib/aws-apigatewayv2';
import { HttpLambdaIntegration } from 'aws-cdk-lib/aws-apigatewayv2-integrations';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import { NodejsFunction } from 'aws-cdk-lib/aws-lambda-nodejs';
import { SqsEventSource } from 'aws-cdk-lib/aws-lambda-event-sources';
import * as sqs from 'aws-cdk-lib/aws-sqs';
import * as events from 'aws-cdk-lib/aws-events';
import * as iam from 'aws-cdk-lib/aws-iam';

export class SampleStack {
  constructor(scope, id) {
    const publicFn = new NodejsFunction(this, 'Public', { functionName: 'public-thing', entry: 'src/public.ts' });
    const orderFn = new NodejsFunction(this, 'Orders', { functionName: 'order-api', entry: 'src/orders.ts', environment: { PAYMENT_API_KEY: 'x' } });
    const adminFn = new lambda.Function(this, 'Admin', { functionName: 'admin-api', handler: 'index.handler' });
    const worker = new NodejsFunction(this, 'Worker', { functionName: 'order-worker', entry: 'src/worker.ts' });
    const sessionAuthorizer = new apigw.RequestAuthorizer(this, 'Session', { handler: publicFn, identitySources: [apigw.IdentitySource.header('Cookie')] });
    const cognitoAuthorizer = new apigw.CognitoUserPoolsAuthorizer(this, 'Staff', { cognitoUserPools: [] });
    const basicAuth = new apigw.TokenAuthorizer(this, 'Basic', { handler: publicFn });
    const queue = new sqs.Queue(this, 'Orders', { queueName: 'orders' });

    const api = new apigw.RestApi(this, 'Sample', {
      defaultCorsPreflightOptions: { allowOrigins: apigw.Cors.ALL_ORIGINS, allowCredentials: true },
    });
    api.root.addResource('public').addResource('thing').addMethod('GET', new apigw.LambdaIntegration(publicFn));
    const orders = api.root.addResource('orders');
    orders.addMethod('POST', new apigw.LambdaIntegration(orderFn), { authorizer: sessionAuthorizer, requestModels: { 'application/json': orderModel } });
    orders.addResource('{id}').addMethod('PATCH', new apigw.LambdaIntegration(orderFn), { authorizer: sessionAuthorizer });
    api.root.resourceForPath('admin/users').addMethod('GET', new apigw.LambdaIntegration(adminFn), { authorizer: cognitoAuthorizer, authorizationType: apigw.AuthorizationType.COGNITO });
    api.root.addResource('config').addMethod('GET', new apigw.LambdaIntegration(publicFn), { apiKeyRequired: true });
    const hooks = api.root.addResource('hooks');
    hooks.addMethod('POST', new apigw.AwsIntegration({ service: 'sqs', path: 'queue' }), { authorizer: basicAuth });
    api.root.addResource('wishlist').addProxy({ defaultIntegration: new apigw.LambdaIntegration(publicFn) });
    for (const name of ['a', 'b']) {
      api.root.addResource(name).addMethod('GET', new apigw.MockIntegration());
    }

    worker.addEventSource(new SqsEventSource(queue, { batchSize: 10 }));
    new events.Rule(this, 'Nightly', { schedule: events.Schedule.cron({ hour: '2' }), targets: [] });
    adminFn.addFunctionUrl({ authType: lambda.FunctionUrlAuthType.NONE });
    orderFn.addToRolePolicy(new iam.PolicyStatement({ actions: ['dynamodb:*'], resources: ['*'] }));

    const http = new HttpApi(this, 'Items', { corsPreflight: { allowOrigins: ['https://example.com'] } });
    http.addRoutes({ path: '/v2/items', methods: [HttpMethod.GET, HttpMethod.POST], integration: new HttpLambdaIntegration('Items', publicFn) });
  }
}
