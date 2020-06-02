import IEndUserAuthData from "./IEndUserAuthData";

export default interface ISessionCurrentData {
    responseType: "token"|"code";
    authData: IEndUserAuthData;
}