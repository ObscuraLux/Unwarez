import Foundation

/// Sends a Mail.app alert when threats are found and an alert address is
/// configured. Uses `NSAppleScript` directly rather than shelling out to
/// `osascript` (the bash backend's approach) - no process spawn, and the
/// subject/body are escaped before being embedded in the script source
/// rather than interpolated raw into a heredoc.
public enum EmailAlert {
    @discardableResult
    public static func send(subject: String, body: String, to address: String) -> Bool {
        guard !address.isEmpty else { return false }
        let source = """
        tell application "Mail"
            set newMsg to make new outgoing message with properties {subject:"\(escape(subject))", content:"\(escape(body))", visible:false}
            tell newMsg
                make new to recipient at end of to recipients with properties {address:"\(escape(address))"}
                send
            end tell
        end tell
        """
        guard let script = NSAppleScript(source: source) else { return false }
        var error: NSDictionary?
        script.executeAndReturnError(&error)
        return error == nil
    }

    private static func escape(_ text: String) -> String {
        text.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
    }
}
