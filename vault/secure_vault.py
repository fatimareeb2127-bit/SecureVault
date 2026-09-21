from crypto.encryption import (
    encrypt_data,
    decrypt_data
)

from database.database import connect


def save_secret(
    title,
    category,
    secret,
    master_password
):

    encrypted = encrypt_data(
        secret.encode("utf8"),
        master_password,
        {
            "category": category
        }
    )

    connection = connect()

    connection.execute(
        """
        INSERT INTO vault
        (title, category, encrypted_data, created_at)
        VALUES (?, ?, ?, datetime('now'))
        """,
        (
            title,
            category,
            encrypted
        )
    )

    connection.commit()
    connection.close()


def get_secrets():

    connection = connect()

    rows = connection.execute(
        """
        SELECT id, title, category, created_at
        FROM vault
        ORDER BY id DESC
        """
    ).fetchall()

    connection.close()

    return rows


def get_secret(
    secret_id,
    master_password
):

    connection = connect()

    row = connection.execute(
        """
        SELECT title, category, encrypted_data
        FROM vault
        WHERE id = ?
        """,
        (secret_id,)
    ).fetchone()

    connection.close()

    if not row:
        return None

    decrypted, metadata = decrypt_data(
        row[2],
        master_password
    )

    return {
        "title": row[0],
        "category": row[1],
        "secret": decrypted.decode("utf8"),
        "metadata": metadata
    }


def delete_secret(secret_id):

    connection = connect()

    connection.execute(
        "DELETE FROM vault WHERE id = ?",
        (secret_id,)
    )

    connection.commit()
    connection.close()