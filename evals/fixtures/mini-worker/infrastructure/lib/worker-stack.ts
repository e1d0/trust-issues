// @ts-nocheck
import * as cdk from 'aws-cdk-lib';
import * as apigw from 'aws-cdk-lib/aws-apigateway';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as sqs from 'aws-cdk-lib/aws-sqs';
import { NodejsFunction } from 'aws-cdk-lib/aws-lambda-nodejs';
import { SqsEventSource } from 'aws-cdk-lib/aws-lambda-event-sources';

export class WorkerStack extends cdk.Stack {
  constructor(scope, id, props) {
    super(scope, id, props);
    const pointsSync = new NodejsFunction(this, 'PointsSync', { functionName: 'points-sync', entry: 'lambdas/points-sync/index.ts', description: 'Books loyalty points from partner events.' });
    const pointsQueue = new sqs.Queue(this, 'PartnerPointsEvents', { queueName: 'PartnerPointsEvents' });
    pointsSync.addEventSource(new SqsEventSource(pointsQueue));

    const role = new iam.Role(this, 'ApiToSqs', { assumedBy: new iam.ServicePrincipal('apigateway.amazonaws.com') });
    pointsQueue.grantSendMessages(role);
    const api = new apigw.RestApi(this, 'PartnerApi');
    api.root.addResource('partner').addResource('points-event').addMethod(
      'POST',
      new apigw.AwsIntegration({ service: 'sqs', path: `${cdk.Aws.ACCOUNT_ID}/${pointsQueue.queueName}`, options: { credentialsRole: role } }),
      { apiKeyRequired: true },
    );
  }
}
