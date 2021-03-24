/*
 * Copyright 2012-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.samples.petclinic.vet;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * @author Victor Ramos
 *
 */
@Controller
class VetAPIController {

    private final VetRepository vets;

    public VetAPIController(VetRepository clinicService) {
        this.vets = clinicService;
    }

    @GetMapping({ "/API/vetsJSON" })
    public @ResponseBody VetsJSON showResourcesVetListJSON() {
        // Here we are returning an object of type 'Vets' rather than a collection of Vet
        // objects so it is simpler for JSon/Object mapping
        VetsJSON vets = new VetsJSON();
        vets.getVetList().addAll(this.vets.findAll());
        return vets;
    }

    @GetMapping({ "/API/vetsXML" })
    public @ResponseBody VetsXML showResourcesVetListXML() {
        // Here we are returning an object of type 'Vets' rather than a collection of Vet
        // objects so it is simpler for JSon/Object mapping
        VetsXML vets = new VetsXML();
        vets.getVetList().addAll(this.vets.findAll());
        return vets;
    }

    @GetMapping({ "/API/vetsJSON/{vetId}" })
    public @ResponseBody
    Vet showResourcesVetJSON(@PathVariable("vetId") int vetId) {
        // Here we are returning an object of type 'Owners' rather than a collection of Owner
        // objects so it is simpler for JSon/Object mapping
        Vet vet = this.vets.findById(vetId);
        return vet;
    }

    @PostMapping(value = { "/API/vetsJSON/"  },
        consumes = MediaType.APPLICATION_JSON_VALUE
        )
    @ResponseStatus(HttpStatus.CREATED)
    @ResponseBody
    public Vet createVet(@RequestBody Vet vet) {
        this.vets.save(vet);
        return vet;
    }

    @PutMapping(value = "/API/vetsJSON/",
        consumes = MediaType.APPLICATION_JSON_VALUE
    )
    @ResponseStatus(HttpStatus.OK)
    @ResponseBody
    public Vet updateVet(@RequestBody Vet vet) {
        this.vets.save(vet);
        return vet;
    }

    @DeleteMapping(value = "/API/vetsJSON/",
        consumes = MediaType.APPLICATION_JSON_VALUE
    )
    @ResponseStatus(HttpStatus.OK)
    @ResponseBody
    public void deleteVet(@RequestBody Vet vet) {

        this.vets.delete(vet);

    }

}
