import Foundation

/// Read-only lookup against the same game list this peer is allowed to browse.
struct LibraryFindQuery: Sendable {
    let system: String
    let md5: String?
    let names: Set<String>

    init?(_ query: [String: String]) {
        let prefix = "com.provenance."
        guard let system = query["system"]?.lowercased(), system.hasPrefix(prefix), system.count <= 120 else { return nil }
        let md5 = query["md5"]?.lowercased()
        if let md5, md5.count != 32 || !md5.allSatisfy(\.isHexDigit) { return nil }
        let names = query["names"] ?? ""
        guard names.count <= 1025, md5 != nil || !names.isEmpty else { return nil }
        self.system = String(system.dropFirst(prefix.count))
        self.md5 = md5
        self.names = Set(names.split(separator: ",").map(String.init))
    }

    func matches(system: String, md5: String?, title: String) -> Bool {
        guard system.lowercased().filter({ !$0.isWhitespace }) == self.system else { return false }
        if let md5 = md5?.lowercased(), md5 == self.md5 { return true }
        let base = (title as NSString).deletingPathExtension
        let folded = base.folding(options: [.diacriticInsensitive, .caseInsensitive], locale: Locale(identifier: "en_US_POSIX"))
        let key = String(String.UnicodeScalarView(folded.unicodeScalars.filter(CharacterSet.alphanumerics.contains))).lowercased()
        return names.contains(key)
    }
}
