import {
  AuthenticationBindings,
  AuthenticationMetadata
} from '@loopback/authentication';
import {inject, Provider, ValueOrPromise} from '@loopback/context';
import {repository} from '@loopback/repository';
import {HttpErrors, Request, RedirectRoute,} from '@loopback/rest';
import {Strategy} from 'passport';
import {BasicStrategy} from 'passport-http';
import {Strategy as BearerStrategy} from 'passport-http-bearer';
import {TokenServiceBindings} from '../keys';
import {UserRepository} from '../repositories';
import { JWTService } from '../services/jwt-service';
import {ParamsDictionary} from 'express-serve-static-core';
import {ParsedQs} from 'qs';
import {UserProfile} from '@loopback/security';

export class MyAuthStrategyProvider implements Provider<Strategy | undefined> {


  constructor(
    @inject(AuthenticationBindings.METADATA)
    private metadata: AuthenticationMetadata,
    @inject(TokenServiceBindings.TOKEN_SERVICE)
    public jwtService: JWTService,
    @repository(UserRepository)
    public userRepository: UserRepository
  ) {}

  value(): ValueOrPromise<Strategy | undefined> {
    // The function was not decorated, so we shouldn't attempt authentication
    if (!this.metadata) {
      return undefined;
    }

    const name = this.metadata.strategy;
    switch (name) {
      //  case 'BasicStrategy':
      //    return new BasicStrategy(this.authenticate.bind(this));
      case 'TokenAdminStrategy':
        return new BearerStrategy(this.VerifyAdminToken.bind(this));
      case 'TokenStudentStrategy':
        return new BearerStrategy(this.VerifyStudentToken.bind(this));
      default:
        return Promise.reject(`The strategy ${name} is not available.`);
        break;
    }
  }

  async authenticate(request: Request<ParamsDictionary, any, any, ParsedQs>):
    Promise<UserProfile | RedirectRoute | undefined> {

    const token: string = this.extractCredentials(request);
    const userProfile = await this.jwtService.verifyToken(token);
    return Promise.resolve(userProfile);

  }

  extractCredentials(request: Request<ParamsDictionary, any, any, ParsedQs>): string {
    if (!request.headers.authorization) {
      throw new HttpErrors.Unauthorized('Authorization is missing');
    }
    const authHeaderValue = request.headers.authorization;

    // authorization : Bearer xxxx.yyyy.zzzz
    if (!authHeaderValue.startsWith('Bearer')) {
      throw new HttpErrors.Unauthorized('Authorization header is not type of Bearer');
    }
    const parts = authHeaderValue.split(' ');
    if (parts.length !== 2) {
      throw new HttpErrors.Unauthorized(`Authorization header has too many part is must follow this patter 'Bearer xx.yy.zz`)
    }
    const token = parts[1];
    return token;
  }


  VerifyAdminToken(
    token: string,
    cb: (err: Error | null, user?: object | false) => void,
  ) {
    this.jwtService.verifyToken(token).then(data => {
      if (data && data.role == 2) {
        return cb(null, data);
      }
      return cb(null, false);
    });
  }



  VerifyStudentToken(
    token: string,
    cb: (err: Error | null, user?: object | false) => void,
  ) {
    this.jwtService.verifyToken(token).then(data => {
      if (data && data.role == 1) {
        return cb(null, data);
      }
      return cb(null, false);
    });
  }
}
