#if canImport(Darwin)
import Darwin.C
#elseif canImport(Glibc)
import Glibc
#elseif canImport(MSVCRT)
import MSVCRT
#endif

import Foundation
import SwiftGD

let formats = [
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

@_cdecl("LLVMFuzzerTestOneInput")
public func GDFuzz(_ start: UnsafeRawPointer, _ count: Int) -> CInt {
    let fdp = FuzzedDataProvider(start, count)

    do {
        let format = fdp.PickValueInList(from: formats)
        try Image(data: fdp.ConsumeRemainingData(), as: format)
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