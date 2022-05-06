// Uncomment these imports to begin using these cool features!

import {TokenService, UserService} from '@loopback/authentication';
import {inject} from '@loopback/core';
import {repository} from '@loopback/repository';
import {getJsonSchemaRef, post, requestBody} from '@loopback/rest';
import _ from 'lodash';
import {PasswordHasherBindings, TokenServiceBindings, UserServiceBindings} from '../keys';
import {User} from '../models/user.model';
import {Credentials, UserRepository} from '../repositories';
import {BcryptHasher} from '../services/hash.password';
import {JWTService} from '../services/jwt-service';
import {MyUserService} from '../services/user.service';
import {validateCredentials} from '../services/validator.service';

// import {inject} from '@loopback/core';


export class UserControlController {
  constructor(
    @repository(UserRepository)
    public userRepository: UserRepository,

    // @inject('service.hasher')
    @inject(PasswordHasherBindings.PASSWORD_HASHER)
    public hasher: BcryptHasher,

    // @inject('service.user.service')
    @inject(UserServiceBindings.USER_SERVICE)
    public userService: MyUserService,

    // @inject(UserServiceBindings.USER_SERVICE)
    // public userService: UserService <User, Credentials>,

    // @inject('service.jwt.service')
    @inject(TokenServiceBindings.TOKEN_SERVICE)
    public jwtService: JWTService,

    // @inject(TokenServiceBindings.TOKEN_SERVICE)
    // public jwtService: TokenService,
  ) {}

  @post('/users/signup', {
    responses: {
      '200': {
        description: 'User',
        content: {
          schema: getJsonSchemaRef(User),
        },
      },
    },
  })
  async signup(@requestBody() userData: User) {
    validateCredentials(_.pick(userData, ['email', 'password']));

    console.log(userData);

    userData.password = await this.hasher.hashPassword(userData.password);
    const savedUser = await this.userRepository.create(userData);
    //delete savedUser.password;
    return savedUser;
  }


  @post('/users/login', {
    responses: {
      '200': {
        description: 'Token',
        content: {
          'application/json': {
            schema: {
              type: 'object',
              properties: {
                token: {
                  type: 'string',
                },
              },
            },
          },
        },
      },
    },
  })
  async login(
    @requestBody() credentials: Credentials,
  ): Promise<{token: string}> {
    // make sure user exist,password should be valid
    const user = await this.userService.verifyCredentials(credentials);
    // console.log(user);
    const userProfile = await this.userService.convertToUserProfile(user);
    // console.log(userProfile);

    const token = await this.jwtService.generateToken(userProfile);
    return Promise.resolve({token: token});
  }


}
