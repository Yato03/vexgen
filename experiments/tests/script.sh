#!/bin/bash

# Carpeta donde están los archivos (por defecto, el directorio actual)
FOLDER="${1:-.}"

# Verificar que la carpeta existe
if [ ! -d "$FOLDER" ]; then
  echo "Error: La carpeta '$FOLDER' no existe."
  exit 1
fi

# Cambiar a la carpeta especificada para evitar problemas con rutas
cd "$FOLDER" || exit 1

# Iterar sobre los archivos con ':' en el nombre
for file in *; do
  # Verificar si el archivo contiene ':'
  if [[ "$file" == *":"* ]]; then
    # Obtener el nuevo nombre reemplazando ':' por '_'
    new_name="${file//:/_}"

    # Verificar si el nuevo nombre ya existe para evitar colisiones
    if [[ -e "$new_name" ]]; then
      echo "Error: No se pudo renombrar '$file' porque '$new_name' ya existe."
    else
      # Renombrar el archivo
      mv "$file" "$new_name"
      echo "Renombrado: '$file' → '$new_name'"
    fi
  fi
done

echo "Proceso completado."

