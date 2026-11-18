// Generates the AppIcon.iconset PNGs: run `swift make-icon.swift AppIcon.iconset` (needs the Command Line Tools), then `iconutil -c icns AppIcon.iconset`.
import AppKit

func render(_ px: Int) -> Data {
    let s = CGFloat(px)
    let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: px, pixelsHigh: px, bitsPerSample: 8,
                               samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
                               colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
    let ctx = NSGraphicsContext.current!.cgContext

    // Background: blue gradient squircle
    let inset = s * 0.06
    let rect = CGRect(x: inset, y: inset, width: s - 2*inset, height: s - 2*inset)
    let bg = NSBezierPath(roundedRect: rect, xRadius: s*0.22, yRadius: s*0.22)
    ctx.saveGState()
    bg.addClip()
    NSGradient(colors: [NSColor(calibratedRed: 0.10, green: 0.32, blue: 0.80, alpha: 1),
                        NSColor(calibratedRed: 0.02, green: 0.13, blue: 0.40, alpha: 1)])!
        .draw(in: rect, angle: -90)
    ctx.restoreGState()

    // Route line (zigzag) from bottom-left to top-right
    let pts = [CGPoint(x: 0.22, y: 0.28), CGPoint(x: 0.42, y: 0.28), CGPoint(x: 0.42, y: 0.52),
               CGPoint(x: 0.66, y: 0.52), CGPoint(x: 0.66, y: 0.74), CGPoint(x: 0.80, y: 0.74)]
        .map { CGPoint(x: $0.x * s, y: $0.y * s) }
    let path = NSBezierPath()
    path.move(to: pts[0]); pts.dropFirst().forEach { path.line(to: $0) }
    path.lineWidth = s * 0.045; path.lineCapStyle = .round; path.lineJoinStyle = .round
    NSColor(calibratedRed: 0.45, green: 0.85, blue: 1, alpha: 1).setStroke()
    path.stroke()

    // Nodes
    for (i, p) in pts.enumerated() {
        let r = s * (i == 0 || i == pts.count - 1 ? 0.06 : 0.04)
        let dot = NSBezierPath(ovalIn: CGRect(x: p.x - r, y: p.y - r, width: 2*r, height: 2*r))
        (i == pts.count - 1 ? NSColor(calibratedRed: 1, green: 0.78, blue: 0.2, alpha: 1) : NSColor.white).setFill()
        dot.fill()
    }
    NSGraphicsContext.restoreGraphicsState()
    return rep.representation(using: .png, properties: [:])!
}

let dir = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "AppIcon.iconset"
try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
for base in [16, 32, 128, 256, 512] {
    try! render(base).write(to: URL(fileURLWithPath: "\(dir)/icon_\(base)x\(base).png"))
    try! render(base * 2).write(to: URL(fileURLWithPath: "\(dir)/icon_\(base)x\(base)@2x.png"))
}
