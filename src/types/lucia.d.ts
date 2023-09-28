/// <reference types="lucia" />
declare namespace Lucia {
  type Auth = import("../auth/index").Auth;
  interface DatabaseUserAttributes {
    name: string;
    picture: string;
    email?: string | null;
  }
  interface DatabaseSessionAttributes {}
}
