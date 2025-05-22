# VexGen+eGuac Project

This is a project which brings together and adapts VexGen and eGuac to simplify and facilitate the creation and analysis of eVEX format.  It allows you to take your GitHub project to a vulnerability analysis in a matter of clicks.


<!-- <p>
  <a href="https://github.com/GermanMT/depex/releases" target="_blank">
    <img src="https://img.shields.io/github/v/release/GermanMT/depex?color=green&logo=github" alt="release">
  </a>

  <a href="https://github.com/GermanMT/depex/blob/main/LICENSE.md" target="_blank">
    <img src="https://img.shields.io/github/license/GermanMT/depex?logo=gnu" alt="license">
  </a>

  <a href="https://github.com/GermanMT/depex/actions/workflows/analisys.yml" target="_blank">
    <img src="https://img.shields.io/github/actions/workflow/status/GermanMT/depex/analisys.yml?branch=main&event=push&label=code%20analisys" alt="code analisys">
  </a>

  <a href="https://doi.org/10.5281/zenodo.7692304">
    <img src="https://zenodo.org/badge/DOI/10.5281/zenodo.7692304.svg" alt="DOI">
  </a>
</p> -->


## Video tutorial

https://github.com/user-attachments/assets/5750712e-8429-410b-b697-ce8414fe5063

## Deployment with docker

### Step 1
 Create a .env file from template.env

#### Get API Keys

- How to get a GitHub [API key](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens)

- How to get a NVD [API key](https://nvd.nist.gov/developers/request-an-api-key)

### Step 2
Run command `docker compose up --build` and seed the database with vulnerability info

#### Seeders

- You can create your graphs from scratch or load existing ones used in the experimentation of other articles or simply built and that can help in the creation of new graphs (this task can be time consuming). To do this use the script "seeds/graphdb_seeder.sh" if you are on Linux or "graphdb_seeder.bat" if you are on Windows.

### Step 3 
Enter [here](http://0.0.0.0:8000/docs)

#### Other tools
1. It is recommended to use a GUI such as [MongoDB Compass](https://www.mongodb.com/en/products/compass) to see what information is being indexed in vulnerability database
   
2. You can see the created graph built for [PyPY](http://0.0.0.0:7474/browser/), [NPM](http://localhost:7473/browser/), [Maven](http://localhost:7472/browser/), [Cargo](http://localhost:7471/browser/) and [NuGet](http://localhost:7470/browser/) clicking in this names. Using the Neo4J browser interfaces.

3. You can visit eGuac at [http://localhost:8080](http://localhost:8080)

## Tests

To run tests use the command `docker exec -it vexgen_backend pytest` once you have the containers running.