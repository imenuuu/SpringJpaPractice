package springboot;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

@SpringBootApplication
@EnableJpaAuditing
public class Applicaiton {
    public static void main(String[] args) {

        SpringApplication.run(Applicaiton.class,args);
    }
}
