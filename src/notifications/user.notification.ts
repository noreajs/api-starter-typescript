import NodemailerNotiication from "../services/notifier/email/NodemailerNotification";
import { Notification } from "@noreajs/core";

type Notifications = {
  createUser: (userId: string) => Promise<void>;
  userDeleted: (userId: string) => Promise<void>;
};

const mailer = new NodemailerNotiication<Notifications>({
  generator: {
    theme: "default",
    product: {
      // Appears in header & footer of e-mails
      name: "API Starter Typescript",
      link: "https://mailgen.js/",
      // Optional product logo
      // logo: 'https://mailgen.js/img/logo.png'
    },
  },
});

mailer.email = {
  createUser: async function (userId: string) {
    /**
     * Create the mail
     */
    const mail = mailer.mail({
      body: {
        name: userId,
        intro: "This is a mail constructed with noreajs tools",
      },
    });

    /**
     * Send the mail
     */
    mailer.sendMail({
      from: '"Norea.JS Typscript Starter Api 👻" <foo@example.com>', // sender address
      to: "lambouarnold@gmail.com", // list of receivers
      subject: "BONJOUR Man", // Subject line
      text: mail.text, // plain text body
      html: mail.html, // html body
    });
  },
};

export default new Notification<Notifications>({
  emailNotification: mailer,
});
