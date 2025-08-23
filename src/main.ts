import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import cookieParser from 'cookie-parser';
import { ConfigService } from '@nestjs/config';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Enable CORS with credentials properly
  app.enableCors({
    origin: 'http://localhost:5173', // must be exact (no trailing slash)
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS',
    allowedHeaders: 'Content-Type, Authorization',
    credentials: true, // this allows cookies/auth headers
  });

  const configService = app.get(ConfigService);
  const port = configService.get('port');
  app.use(cookieParser());

  await app.listen(port);
}
bootstrap();
