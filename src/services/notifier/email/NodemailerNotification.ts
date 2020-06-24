import Mail from "nodemailer/lib/mailer";
import nodemailer from "nodemailer";
import { IEmailNotification } from "@noreajs/core";

export default class NodemailerNotiication<Emails> extends IEmailNotification<
  Emails,
  Mail,
  Mail.Options
> {
  initTransport() {
    this.transport = nodemailer.createTransport({
      host: "smtp.ethereal.email",
      port: 587,
      auth: {
        user: "maximillia.beahan@ethereal.email",
        pass: "KfXmpamKVv1GjWYY1S",
      },
    });
  }

  async sendMail(
    mailData: Mail.Options,
    callback?: ((error: any, info: any) => void) | undefined
  ) {
    if (this.transport) {
      await this.transport.sendMail(
        mailData,
        (err: Error | null, info: any) => {
          if (callback) {
            callback(err, info);
          }
        }
      );
    } else {
      throw Error("nodemailer transport is not initialized");
    }
  }
}
