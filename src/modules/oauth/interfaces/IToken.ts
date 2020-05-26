export default interface IToken {
  access_token: string;
  token_type: "Bearer";
  refresh_token?: string;
  expires_in: number;
  state?: string;
  [key:string]:any;
}
