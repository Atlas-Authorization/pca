/**
 * Test harness: serves `envoy.service.auth.v3.Authorization/Check` over real gRPC (HTTP/2) using
 * @grpc/grpc-js + protobufjs and the proto subset in fixtures/envoy-ext_authz-grpc-subset.proto.
 * The decision logic is the library's `envoyGrpcExtAuthz`; this file is only transport.
 */
import { join } from 'node:path';
import * as grpc from '@grpc/grpc-js';
import protobuf from 'protobufjs';
import type { EnvoyGrpcCheckRequest, EnvoyGrpcCheckResponse } from '../src/index';

const PROTO = join(__dirname, '..', 'fixtures', 'envoy-ext_authz-grpc-subset.proto');

export interface GrpcCheckServer {
  port: number;
  /** Raw decoded CheckRequest objects (camelCase) as received from Envoy, in order. */
  received: unknown[];
  close(): Promise<void>;
}

export async function startGrpcCheckServer(
  handler: (req: EnvoyGrpcCheckRequest) => Promise<EnvoyGrpcCheckResponse>,
): Promise<GrpcCheckServer> {
  const root = await protobuf.load(PROTO);
  const Req = root.lookupType('envoy.service.auth.v3.CheckRequest');
  const Res = root.lookupType('envoy.service.auth.v3.CheckResponse');
  const received: unknown[] = [];
  const server = new grpc.Server();
  const def: grpc.ServiceDefinition = {
    Check: {
      path: '/envoy.service.auth.v3.Authorization/Check',
      requestStream: false,
      responseStream: false,
      requestSerialize: (v: unknown) => Buffer.from(Req.encode(Req.fromObject(v as object)).finish()),
      requestDeserialize: (b: Buffer) => Req.decode(b),
      responseSerialize: (v: unknown) => Buffer.from(Res.encode(Res.fromObject(v as object)).finish()),
      responseDeserialize: (b: Buffer) => Res.decode(b),
    },
  };
  server.addService(def, {
    Check: (call: grpc.ServerUnaryCall<unknown, unknown>, cb: grpc.sendUnaryData<unknown>) => {
      const obj = Req.toObject(call.request as protobuf.Message, { defaults: false, arrays: true, objects: true, longs: String });
      received.push(obj);
      handler(obj as EnvoyGrpcCheckRequest).then(
        (r) => cb(null, r),
        (e: unknown) => cb({ code: grpc.status.INTERNAL, message: String(e) }),
      );
    },
  });
  const port = await new Promise<number>((resolve, reject) => {
    server.bindAsync('127.0.0.1:0', grpc.ServerCredentials.createInsecure(), (err, p) => (err ? reject(err) : resolve(p)));
  });
  return {
    port,
    received,
    close: () =>
      new Promise<void>((resolve) => {
        server.tryShutdown(() => resolve());
        setTimeout(() => { server.forceShutdown(); resolve(); }, 1000).unref();
      }),
  };
}
