package com.zuehlke.securesoftwaredevelopment.controller;

import com.zuehlke.securesoftwaredevelopment.config.AuditLogger;
import com.zuehlke.securesoftwaredevelopment.config.SecurityUtil;
import com.zuehlke.securesoftwaredevelopment.domain.Person;
import com.zuehlke.securesoftwaredevelopment.domain.User;
import com.zuehlke.securesoftwaredevelopment.repository.PersonRepository;
import com.zuehlke.securesoftwaredevelopment.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpSession;
import java.nio.file.AccessDeniedException;
import java.sql.SQLException;
import java.util.List;

@Controller

public class PersonsController {

    private static final Logger LOG = LoggerFactory.getLogger(PersonsController.class);
    private static final AuditLogger auditLogger = AuditLogger.getAuditLogger(PersonRepository.class);

    private final PersonRepository personRepository;
    private final UserRepository userRepository;

    public PersonsController(PersonRepository personRepository, UserRepository userRepository) {
        this.personRepository = personRepository;
        this.userRepository = userRepository;
    }

    @GetMapping("/persons/{id}")
    public String person(@PathVariable int id, Model model, HttpSession httpSession) throws AccessDeniedException {

        //after person changes their data
        //system should permit person to stay on the current page
        if (!SecurityUtil.hasPermission("VIEW_PERSON")) {
            int currentUserId = SecurityUtil.getCurrentUser().getId();
            if (currentUserId != id) {
                LOG.error("User with id:{} does not have rights to visit this page",currentUserId);
                throw new AccessDeniedException("Access forbidden");
            }
        }

        model.addAttribute("person", personRepository.get("" + id));
        String csrf = httpSession.getAttribute("CSRF_TOKEN").toString();
        model.addAttribute("CSRF_TOKEN", csrf);
        return "person";
    }

    @GetMapping("/myprofile")
    @PreAuthorize("hasAuthority('VIEW_MY_PROFILE')")
    public String self(Model model, Authentication authentication, HttpSession httpSession) {
        User user = (User) authentication.getPrincipal();
        model.addAttribute("person", personRepository.get("" + user.getId()));
        String csrf = httpSession.getAttribute("CSRF_TOKEN").toString();
        model.addAttribute("CSRF_TOKEN", csrf);
        return "person";
    }

    @DeleteMapping("/persons/{id}")
    public ResponseEntity<Void> person(@PathVariable int id) throws AccessDeniedException {

        if (!SecurityUtil.hasPermission("UPDATE_PERSON")) {
            int currentId = SecurityUtil.getCurrentUser().getId();
            if (id != currentId) {
                LOG.error("User with id:{} does not have rights to perform the specified DELETE action",currentId);
                throw new AccessDeniedException("Access Forbidden");
            }
        }

        personRepository.delete(id);
        userRepository.delete(id);
        LOG.info("Successful deleted user with id: "+id);

        return ResponseEntity.noContent().build();
    }

    @PostMapping("/update-person")
    public String updatePerson(Person person, HttpSession httpSession, @RequestParam("csrfToken") String csrfToken) throws AccessDeniedException {
        String csrf = httpSession.getAttribute("CSRF_TOKEN").toString();
        if (!csrf.equals(csrfToken)) {
            throw new AccessDeniedException("Access Forbidden");
        }

        if (!SecurityUtil.hasPermission("UPDATE_PERSON")) {
            int personId = Integer.parseInt(person.getId());
            int currentId = SecurityUtil.getCurrentUser().getId();
            if (personId != currentId) {
                LOG.error("User with id:{} does not have rights to perform the specified UPDATE action",currentId);
                throw new AccessDeniedException("Access Forbidden");
            }
        }

        personRepository.update(person);
        return "redirect:/persons/" + person.getId();
    }

    @GetMapping("/persons")
    @PreAuthorize("hasAuthority('VIEW_PERSONS_LIST')")
    public String persons(Model model) {
        model.addAttribute("persons", personRepository.getAll());
        return "persons";
    }

    @GetMapping(value = "/persons/search", produces = "application/json")
    @PreAuthorize("hasAuthority('VIEW_PERSONS_LIST')")
    @ResponseBody
    public List<Person> searchPersons(@RequestParam String searchTerm) throws SQLException {
        return personRepository.search(searchTerm);
    }
}
