import {inject} from '@loopback/core';
import {TokenServiceBindings} from '../keys';
import {securityId, UserProfile} from '@loopback/security';
import {HttpErrors} from '@loopback/rest';
import {promisify} from 'util';


const jwt = require('jsonwebtoken');
const signAsync = promisify(jwt.sign);
const verifyAsync = promisify(jwt.verify);

export class JWTService {
  // @inject('authentication.jwt.secret')
  @inject(TokenServiceBindings.TOKEN_SECRET)
  public readonly jwtSecret: string;

  @inject(TokenServiceBindings.TOKEN_EXPIRES_IN)
  public readonly jwtExpiresIn: string;


  async generateToken(userProfile: UserProfile): Promise<string> {
    if (!userProfile) {
      throw new HttpErrors.Unauthorized(
        'Error while generating token :userProfile is null'
      )
    }
    let token = '';
    const userInfoForToken = {
      id: userProfile[securityId],
      email: userProfile.email,
      roles: userProfile.roles,
    };
    try {
      token = await signAsync(userProfile, this.jwtSecret, {
        expiresIn: this.jwtExpiresIn
      });
      return token;
    } catch (err) {
      throw new HttpErrors.Unauthorized(
        `error generating token ${err}`
      )
    }
  }


  async verifyToken(token: string): Promise<UserProfile> {

    if (!token) {
      throw new HttpErrors.Unauthorized(
        `Error verifying token:'token' is null`
      )
    };

    let userProfile: UserProfile;
    try {
      const decryptedToken = await verifyAsync(token, this.jwtSecret);
      const completeName = decryptedToken.first_name + decryptedToken.last_name;
      userProfile = Object.assign(
        {[securityId]: '', id: '', email: '', roles: []},
        {
          [securityId]: decryptedToken.id,
          id: decryptedToken.id,
          email: decryptedToken.email,
          roles: decryptedToken.roles,
        },
      );
    } catch (err) {
      throw new HttpErrors.Unauthorized(`Error verifying token:${err.message}`);
    }
    return userProfile;
  }


}
