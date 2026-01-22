import { Resend } from 'resend'
import envConfig from '../config'

export class EmailService {
  constructor(private resend: Resend) {
    this.resend = new Resend(envConfig.RESEND_API_KEY)
  }

  sendOTP(payload: { email: string; code: string }) {
    return this.resend.emails.send({
      from: 'Ecommerce <onboarding@resend.dev>',
      to: [payload.email],
      subject: 'Mã OTP',
      html: `<strong>${payload.code}</strong>`,
    })
  }
}
