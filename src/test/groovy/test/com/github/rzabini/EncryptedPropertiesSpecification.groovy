package test.com.github.rzabini

import com.github.rzabini.AESUtil
import com.github.rzabini.EncryptedProperties
import spock.lang.Specification

import java.nio.file.Files
import java.nio.file.Path

class EncryptedPropertiesSpecification extends Specification {

    def "should encrypt password entries in property file"() {
        setup:
        Path inputFile = Files.createTempFile("sample", ".properties")
        inputFile.toFile().text =
        '''
        username=test
        password=encryptme
        '''.replaceAll('\t','')

        when:
        Properties encryptedProperties = EncryptedProperties.create("master", inputFile)

        then:
        encryptedProperties.getProperty('username') == 'test'
        encryptedProperties.getProperty('password') == 'encryptme'
        inputFile.toFile().readLines().find({line -> line.startsWith('password=ENC(')})

        cleanup:
        Files.deleteIfExists(inputFile)
    }

    def "should decrypt password entries in property file"(){
        setup:
        Path inputFile = Files.createTempFile("sample", ".properties")
        initializeEncryptedPropertiesFile(inputFile)

        when:
        Properties encryptedProperties = EncryptedProperties.create("mymasterpassword", inputFile)

        then:
        encryptedProperties.getProperty('username') == 'myusername'
        encryptedProperties.getProperty('password') == 'secret'

        cleanup:
        Files.deleteIfExists(inputFile)
    }

    def "should throw an exception if trying to decrypt with a wrong password"(){
        setup:
        Path inputFile = Files.createTempFile("sample", ".properties")
        initializeEncryptedPropertiesFile(inputFile)

        when:
        Properties encryptedProperties = EncryptedProperties.create("wrong", inputFile)

        then:
        thrown(IllegalStateException)
    }

    private initializeEncryptedPropertiesFile(Path inputFile) {
        inputFile.toFile().text =
                '''
        username=myusername
        password=ENC(mhKSaCaq3rtBOowk7+X+9ghO9U6Qufusn8jV0v9nJac=)
        '''.replaceAll('\t', '')
    }
}
