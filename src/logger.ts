import chalk from "chalk";

class Logger {
    info(message: string) {
        console.log(chalk.bold(chalk.hex("#ebaaee")(`[mrrowisp]: ${message}`)));
    }
    error(message: string) {
        console.log(chalk.bold(chalk.hex("#f38fad")(`[mrrowisp]: ${message}`)));
    }
    warn(message: string) {
        console.log(chalk.bold(chalk.hex("#f9dca1")(`[mrrowisp]: ${message}`)));
    }
}

const logger = new Logger();

export default logger;
