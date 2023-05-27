#if canImport(Darwin)
import Darwin.C
#elseif canImport(Glibc)
import Glibc
#elseif canImport(MSVCRT)
import MSVCRT
#endif

import Foundation
import SwiftGD

let import_formats = [
    ImportableFormat.any,
    ImportableFormat.bmp,
    ImportableFormat.gif,
    ImportableFormat.png,
    ImportableFormat.tiff,
    ImportableFormat.webp,
    ImportableFormat.tga,
    ImportableFormat.wbmp,
    ImportableFormat.jpg,
]

let export_formats = [
    ExportableFormat.jpg(quality: 20),
    ExportableFormat.wbmp(index: 1),
    ExportableFormat.gif,
    ExportableFormat.png,
    ExportableFormat.tiff,
    ExportableFormat.webp,
    ExportableFormat.bmp(compression: true)
]

let fill_colors = [
    Color.red,
    Color.green,
    Color.black,
    Color.blue,
    Color.white
]

@_cdecl("LLVMFuzzerTestOneInput")
public func GDFuzz(_ start: UnsafeRawPointer, _ count: Int) -> CInt {
    let fdp = FuzzedDataProvider(start, count)

    do {
        let imp_format = fdp.PickValueInList(from: import_formats)
        let img = try Image(data: fdp.ConsumeRandomLengthData(), as: imp_format)

        if fdp.ConsumeBoolean() {
            img.fill(from: .zero, color: fdp.PickValueInList(from: fill_colors))
        }

        let exp_format = fdp.PickValueInList(from: export_formats)
        try img.export(as: exp_format)
    }
    catch let error {
        if error.localizedDescription.contains("operation could not be completed") {
            return -1;
        }
        print(error.localizedDescription)
        print(type(of: error))
    }
    return 0;
}