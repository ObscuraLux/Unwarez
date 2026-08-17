import Foundation
import CoreGraphics
import CoreText

/// Renders plain text to a paginated PDF via CoreGraphics/CoreText
/// directly, rather than shelling out to `textutil -convert pdf`. That
/// was the original (bash-era) approach, but current macOS's `textutil`
/// no longer lists `pdf` as a supported `-convert` format at all
/// (confirmed directly: `textutil -help` enumerates txt/rtf/rtfd/html/
/// doc/docx/odt/wordml/webarchive - no pdf - and converting even trivial
/// content fails with "Invalid output format") - this was already a
/// dead code path before this rewrite, not something the rewrite broke.
enum PDFExport {
    static func render(text: String, to outputURL: URL) -> Bool {
        var mediaBox = CGRect(x: 0, y: 0, width: 612, height: 792) // US Letter at 72dpi
        guard let context = CGContext(outputURL as CFURL, mediaBox: &mediaBox, nil) else {
            return false
        }

        let margin: CGFloat = 48
        // kCTFontAttributeName rather than NSAttributedString.Key.font -
        // the latter is an AppKit extension, and this target deliberately
        // doesn't import AppKit for a text-to-PDF renderer.
        let font = CTFontCreateWithName("Menlo" as CFString, 9, nil)
        let attributedString = NSAttributedString(string: text, attributes: [kCTFontAttributeName as NSAttributedString.Key: font])
        let framesetter = CTFramesetterCreateWithAttributedString(attributedString)

        let textRect = mediaBox.insetBy(dx: margin, dy: margin)
        let path = CGPath(rect: textRect, transform: nil)

        var location = 0
        let totalLength = attributedString.length
        while location < totalLength {
            context.beginPDFPage(nil)
            let frame = CTFramesetterCreateFrame(framesetter, CFRange(location: location, length: 0), path, nil)
            CTFrameDraw(frame, context)
            context.endPDFPage()

            let visibleRange = CTFrameGetVisibleStringRange(frame)
            guard visibleRange.length > 0 else { break } // safety: never spin forever if nothing fits on a page
            location += visibleRange.length
        }
        context.closePDF()
        return true
    }
}
