export type JwtPayload = {
  email: string;
  id: number;
  iat?: number;
  exp?: number;
  refreshToken?: string;
};
