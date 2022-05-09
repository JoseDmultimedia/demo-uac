import {
  AuthorizationContext,
  AuthorizationDecision,
  AuthorizationMetadata,
} from '@loopback/authorization';
import {securityId, UserProfile} from '@loopback/security';
import _ from 'lodash';


// Instance level authorizer
// Can be also registered as an authorizer, depends on users' need.
export async function basicAuthorization(
  authorizationCtx: AuthorizationContext,
  metadata: AuthorizationMetadata,
): Promise<AuthorizationDecision> {
  // No access if authorization details are missing
  let currentUser: UserProfile;
  if (authorizationCtx.principals.length > 0) {
    console.log('informacion que recibe' + JSON.stringify(authorizationCtx))
    const user = _.pick(authorizationCtx.principals[0], [
      'id',
      'name',
      'role',
    ]);
    console.log('Se supone que user se forma con autorizationCtx'+JSON.stringify(user))
    currentUser = {[securityId]: user.id, name: user.name, roles: user.role};
    console.log(`CurrentUser deberia tener todos los datos del token ${JSON.stringify(currentUser)}`);
    console.log('user mostraria su rol', authorizationCtx.roles);
  } else {
    console.log('Si no hay información se sale')
    return AuthorizationDecision.DENY;
  }

  if (!currentUser.roles) {
    console.log('Si no hay nada de rol se sale'+ !currentUser.roles)
    return AuthorizationDecision.DENY;
  }

  // Authorize everything that does not have a allowedRoles property
  if (!metadata.allowedRoles) {
    console.log('allowed, se supone que si llega aqui autorizo', metadata.allowedRoles)
    return AuthorizationDecision.ALLOW;
  }

  let roleIsAllowed = false;
  for (const role of currentUser.roles) {
    if (metadata.allowedRoles!.includes(role)) {

      roleIsAllowed = true;
      break;
    }
  }

  if (!roleIsAllowed) {
    console.log('Se sale cuando rol no esta permitido')
    return AuthorizationDecision.DENY;
  }

  /**
   * Allow access only to model owners, using route as source of truth
   *
   * eg. @post('/users/{userId}/orders', ...) returns `userId` as args[0]
   */
  if (currentUser[securityId] === authorizationCtx.invocationContext.args[0]) {
    console.log('Aqui6')
    return AuthorizationDecision.ALLOW;
  }

  return AuthorizationDecision.DENY;
}

// import {
//   AuthorizationContext,
//   AuthorizationDecision,
//   AuthorizationMetadata,
//   Authorizer,
// } from "@loopback/authorization";
// import {Provider} from "@loopback/context";
// import {securityId, UserProfile} from "@loopback/security";
// import _ from "lodash";

// export default class KeycloakAuthorizationProvider
//   implements Provider<Authorizer>
// {
//   value(): Authorizer {
//     return this.authorize.bind(this);
//   }

//   async authorize(
//     context: AuthorizationContext,
//     metadata: AuthorizationMetadata,
//   ) {
//     // No access if authorization details are missing
//     let currentUser: UserProfile;
//     if (context.principals.length > 0) {
//       const user = _.pick(context.principals[0], ["id", "name", "roles"]);
//       currentUser = {[securityId]: user.id, name: user.name, roles: user.roles};
//     } else {
//       return AuthorizationDecision.DENY;
//     }

//     if (!currentUser.roles) {
//       return AuthorizationDecision.DENY;
//     }

//     // Authorize everything that does not have an allowedRoles property
//     if (!metadata.allowedRoles) {
//       return AuthorizationDecision.ALLOW;
//     }

//     let roleIsAllowed = false;
//     for (const role of currentUser.roles) {
//       if (metadata.allowedRoles!.includes(role)) {
//         roleIsAllowed = true;
//         break;
//       }
//     }

//     if (roleIsAllowed) {
//       return AuthorizationDecision.ALLOW;
//     }

//     return AuthorizationDecision.DENY;
//   }
// }
