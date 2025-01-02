GRANT ALL PRIVILEGES ON DATABASE scrapi TO scrapi;
CREATE TABLE IF NOT EXISTS teams (
    team_id SERIAL PRIMARY KEY NOT NULL,
    teamname TEXT UNIQUE NOT NULL,
    team_points INT NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
    user_id SERIAL PRIMARY KEY NOT NULL,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    firstname TEXT NOT NULL,
    lastname TEXT NOT NULL,
    mfa_token TEXT NOT NULL,
    role TEXT NOT NULL,
    token TEXT,
    token_expiry TEXT,
    team_id INT NOT NULL,
    CONSTRAINT team_id
      FOREIGN KEY(team_id) 
        REFERENCES teams(team_id)
);
CREATE TABLE IF NOT EXISTS flags (
    flag_id SERIAL PRIMARY KEY NOT NULL,
    flag_id_trackable TEXT NOT NULL,
    flag TEXT UNIQUE NOT NULL,
    flag_captured BOOLEAN NOT NULL,
    flag_category TEXT NOT NULL,
    flag_category_guessed BOOLEAN NOT NUll,
    team_id INT NOT NULL,
    user_id INT NOT NULL,
    CONSTRAINT team_id
      FOREIGN KEY(team_id) 
        REFERENCES teams(team_id),
    CONSTRAINT user_id
      FOREIGN KEY(user_id) 
        REFERENCES users(user_id)
);