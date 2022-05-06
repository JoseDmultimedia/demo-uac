import {UserService} from '@loopback/authentication';
import {inject} from '@loopback/core';
import {repository} from '@loopback/repository';
import {HttpErrors} from '@loopback/rest';
import {securityId, UserProfile} from '@loopback/security';
import {PasswordHasherBindings} from '../keys';
import {User} from '../models/user.model';
import {UserRepository, Credentials} from '../repositories/user.repository';
import {BcryptHasher} from './hash.password';


export class MyUserService implements UserService<User, Credentials>{
  constructor(
    @repository(UserRepository)
    public userRepository: UserRepository,

    // @inject('service.hasher')
    @inject(PasswordHasherBindings.PASSWORD_HASHER)
    public hasher: BcryptHasher
  )
  {}

  async verifyCredentials(credentials: Credentials): Promise<User> {
    // implement this method
    const foundUser = await this.userRepository.findOne({
      where: {
        email: credentials.email
      }
    });
    if (!foundUser) {
      throw new HttpErrors.NotFound('user not found');
    }
    const passwordMatched = await this.hasher.comparePassword(credentials.password, foundUser.password)
    if (!passwordMatched)
      throw new HttpErrors.Unauthorized('password is not valid');
    return foundUser;
  }


  convertToUserProfile(user: User): UserProfile {
    let completeName = user.first_name + user.last_name;
    return {
      [securityId]: user.id!.toString(),
      name: completeName,
      id: user.id,
      email: user.email,
      roles: user.roles,
    };
  }
}
