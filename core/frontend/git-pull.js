import { execSync } from 'child_process'
import chalk from 'chalk'
import ora from 'ora'

async function getPull() {
	try {
		// 在当前目录执行git pull命令，并同步输出结果
		const spinner = ora(chalk.cyan('正在拉取git...')).start()
		execSync('git pull', { stdio: 'inherit', cwd: process.cwd() })
		spinner.succeed(chalk.green('git pull 执行成功'))
		return true
	} catch (error) {
		console.error('git pull 执行失败:', error.message)
		process.exit(1)
	}
}

getPull()
