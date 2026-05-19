import chalk from "chalk";

export type LogLevel = "debug" | "warn" | "error" | "info" | "none";

const levelPriority: Record<LogLevel, number> = {
	debug: 0,
	warn: 1,
	error: 2,
	info: 3,
	none: 4,
};

class Logger {
	level: LogLevel = "info";

	private shouldLog(method: LogLevel): boolean {
		return levelPriority[method] >= levelPriority[this.level];
	}

	info(message: string) {
		if (!this.shouldLog("info")) return;
		console.log(chalk.bold(chalk.hex("#ebaaee")(`[mrrowisp]: ${message}`)));
	}
	error(message: string) {
		if (!this.shouldLog("error")) return;
		console.log(chalk.bold(chalk.hex("#f38fad")(`[mrrowisp]: ${message}`)));
	}
	warn(message: string) {
		if (!this.shouldLog("warn")) return;
		console.log(chalk.bold(chalk.hex("#f9dca1")(`[mrrowisp]: ${message}`)));
	}
	debug(message: string) {
		if (!this.shouldLog("debug")) return;
		console.log(chalk.bold(chalk.hex("#89b4fa")(`[mrrowisp]: ${message}`)));
	}
}

const logger = new Logger();

export default logger;
