// @ts-nocheck
import * as cdk from 'aws-cdk-lib';
import * as apigw from 'aws-cdk-lib/aws-apigateway';
import { NodejsFunction } from 'aws-cdk-lib/aws-lambda-nodejs';

export class MiniStack extends cdk.Stack {
  constructor(scope, id, props) {
    super(scope, id, props);
    const fn = (name) => new NodejsFunction(this, name, { functionName: name, entry: `lambdas/mini/${name}/index.ts` });
    const sessionAuthorizerFn = fn('session-authorizer');
    const sessionAuthorizer = new apigw.RequestAuthorizer(this, 'SessionAuthorizer', {
      handler: sessionAuthorizerFn,
      identitySources: [apigw.IdentitySource.header('Authorization')],
      resultsCacheTtl: cdk.Duration.minutes(5),
    });
    const orderApi = fn('order-api');
    const contactApi = fn('contact-api');
    const profileApi = fn('profile-api');
    const addressApi = fn('address-api');

    const api = new apigw.RestApi(this, 'MiniApi', {
      defaultCorsPreflightOptions: { allowOrigins: ['https://shop.example.com'], allowCredentials: true },
    });
    api.root.addResource('order').addResource('{orderId}').addMethod('GET', new apigw.LambdaIntegration(orderApi), { authorizer: sessionAuthorizer });
    api.root.addResource('contact').addMethod('POST', new apigw.LambdaIntegration(contactApi));
    api.root.addResource('profile').addMethod('GET', new apigw.LambdaIntegration(profileApi), { authorizer: sessionAuthorizer });
    api.root.addResource('address').addResource('{addressId}').addMethod('GET', new apigw.LambdaIntegration(addressApi), { authorizer: sessionAuthorizer });
  }
}
