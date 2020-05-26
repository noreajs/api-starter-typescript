export default interface IAccessTokenDebug {
  userId: string;
  clientId: string;
  clientName: string;
  scope: string;
  expiresAt: Date;
  issuedAt: Date;
  isValid: boolean;
  metadata: any;
}
