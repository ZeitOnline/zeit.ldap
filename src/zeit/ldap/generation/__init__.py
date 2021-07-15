import zope.generations.generations

minimum_generation = 3
generation = 3

manager = zope.generations.generations.SchemaManager(
    minimum_generation, generation, "zeit.ldap.generation")
