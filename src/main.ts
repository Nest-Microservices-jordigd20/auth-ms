import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { envs } from './config';
import { Transport } from '@nestjs/microservices';
import { Logger } from '@nestjs/common';

async function bootstrap() {
  const logger = new Logger('AuthMS - Main')
  
  const app = await NestFactory.createMicroservice(AppModule, {
    transport: Transport.NATS,
    options: {
      servers: envs.natsServers
    }
  });

  await app.listen();

  logger.log(`AuthMS is running on port: ${envs.port}`);
}
bootstrap();
