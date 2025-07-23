import fs from 'fs'
import path from 'path'
import ora from 'ora'
import chalk from 'chalk'

// 前端打包文件的本地路径
const localPath = './dist'

// 复制本地文件到指定位置
async function copyLocalFiles(targetPath) {
	const spinner = ora(chalk.cyan('正在准备复制文件...')).start()

	return new Promise((resolve, reject) => {
		try {
			// 如果目标目录存在，先删除它
			if (fs.existsSync(targetPath)) {
				spinner.info(chalk.blue(`正在删除目标位置的原有文件: ${targetPath}`))
				deleteFolderRecursive(targetPath)
				spinner.succeed(chalk.green(`原有文件已删除: ${targetPath}`))
			}

			// 创建目标目录
			fs.mkdirSync(targetPath, { recursive: true })
			spinner.info(chalk.blue(`已创建目标目录: ${targetPath}`))

			spinner.start(chalk.cyan(`正在将文件从 ${localPath} 复制到 ${targetPath}...`))

			// 递归复制函数
			const copyRecursive = (source, target) => {
				// 获取源目录中的所有文件和文件夹
				const items = fs.readdirSync(source)

				// 遍历所有文件和文件夹
				items.forEach(item => {
					const sourcePath = path.join(source, item)
					const targetItemPath = path.join(target, item)

					// 检查是文件还是目录
					const stat = fs.statSync(sourcePath)

					if (stat.isDirectory()) {
						// 如果是目录，创建对应的目标目录并递归复制
						if (!fs.existsSync(targetItemPath)) {
							fs.mkdirSync(targetItemPath, { recursive: true })
						}
						copyRecursive(sourcePath, targetItemPath)
					} else {
						// 如果是文件，直接复制
						fs.copyFileSync(sourcePath, targetItemPath)
					}
				})
			}

			// 开始复制
			copyRecursive(localPath, targetPath)

			spinner.succeed(chalk.green(`文件已成功复制到: ${targetPath}`))
			resolve()
		} catch (error) {
			spinner.fail(chalk.red('复制文件时出现错误'))
			// console.error(error)
			reject(error)
		}
	})
}

// 递归删除文件夹及其内容
function deleteFolderRecursive(folderPath) {
	if (fs.existsSync(folderPath)) {
		fs.readdirSync(folderPath).forEach(file => {
			const curPath = path.join(folderPath, file)
			if (fs.lstatSync(curPath).isDirectory()) {
				// 递归删除子目录
				deleteFolderRecursive(curPath)
			} else {
				// 删除文件
				fs.unlinkSync(curPath)
			}
		})
		// 删除空目录
		fs.rmdirSync(folderPath)
	}
}

// 主执行逻辑
async function main() {
	// 再执行文件复制
	await copyLocalFiles('../public/dist')
}

main()
