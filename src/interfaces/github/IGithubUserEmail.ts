export default interface IGithubUserEmail {
    email: string,
    primary: boolean,
    verified: boolean,
    visibility?: string | null
}