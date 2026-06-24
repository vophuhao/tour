import fs from "fs";
import path from "path";

export class EmailTemplateService {
  /**
   * Renders the specified HTML email template with dynmic data
   */
  render(templateName: string, data: Record<string, any>): string {
    const templatePath = path.join(process.cwd(), "src/templates/emails", `${templateName}.html`);
    if (!fs.existsSync(templatePath)) {
      throw new Error(`Email template file not found: ${templatePath}`);
    }
    const templateContent = fs.readFileSync(templatePath, "utf-8");
    return this.renderString(templateContent, data);
  }

  private renderString(template: string, data: Record<string, any>): string {
    return template.replace(/<%=?\s*([\w.]+)\s*%>/g, (match, key) => {
      const value = key.split('.').reduce((obj: any, k: string) => {
        if (obj === null || obj === undefined) return undefined;
        return obj[k];
      }, data);
      return value !== undefined ? String(value) : '';
    });
  }
}
