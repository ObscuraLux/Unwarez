import Foundation
import UnwarezCore

@main
struct UnwarezCLIEntry {
    static func main() async {
        let arguments = Array(CommandLine.arguments.dropFirst())
        var autoMode = false
        var targetValue: Int?
        var customPath: String?
        var filesList: String?

        for arg in arguments {
            if arg == "--auto" {
                autoMode = true
            } else if arg.hasPrefix("--target=") {
                targetValue = Int(arg.dropFirst("--target=".count))
            } else if arg.hasPrefix("--path=") {
                customPath = String(arg.dropFirst("--path=".count))
            } else if arg.hasPrefix("--files=") {
                filesList = String(arg.dropFirst("--files=".count))
            }
        }

        if autoMode {
            guard let targetValue, let target = ScanTarget(rawValue: targetValue) else {
                FileHandle.standardError.write(Data("unwarez-cli: --auto requires a valid --target=N\n".utf8))
                exit(1)
            }
            let options = ScanOptions(target: target, customPath: customPath, fileListPath: filesList, isAutoMode: true)
            _ = await ScanRunner.run(options: options, verbose: false)
            exit(0)
        }

        await InteractiveMenu.run()
    }
}
