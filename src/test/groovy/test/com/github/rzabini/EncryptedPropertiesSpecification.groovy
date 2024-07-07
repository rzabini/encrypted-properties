package test.com.github.rzabini

import com.github.rzabini.EncryptedProperties
import spock.lang.Specification

import java.nio.file.Files
import java.nio.file.Path

class EncryptedPropertiesSpecification extends Specification {

    def go() {
        Path inputFile = Files.createTempFile("sample", ".properties")
        inputFile.toFile().text =
        '''
        username=test
        password=encryptme
        '''.replaceAll('\t','')
        Properties encryptedProperties = EncryptedProperties.create("master", inputFile)
        expect:
        encryptedProperties.getProperty('username') == 'test'
        encryptedProperties.getProperty('password') == 'encryptme'
        println inputFile.toFile().filterLine {line -> line.startsWith('pazzword=ENC(')}

        cleanup:
        Files.deleteIfExists(inputFile)
    }
}
