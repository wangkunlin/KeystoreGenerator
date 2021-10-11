package com.github.wangkunlin.generator

import com.android.annotations.NonNull

import java.nio.file.Files

/**
 * On 2021-10-11
 */
class FileUtils {

    static boolean isSameFile(@NonNull File file1, @NonNull File file2) {
        try {
            if (file1.exists() && file2.exists()) {
                return Files.isSameFile(file1.toPath(), file2.toPath())
            } else {
                return file1.getCanonicalFile() == file2.getCanonicalFile()
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e)
        }
    }
}
