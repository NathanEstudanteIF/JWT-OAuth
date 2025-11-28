import { DataTypes } from "sequelize";
import sequelize from "../config/database.js";

const User = sequelize.define("User", {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true,
  },
  githubId: {
    type: DataTypes.STRING,
    unique: true,
  },
  name: DataTypes.STRING,
  login: DataTypes.STRING,
  profileUrl: DataTypes.STRING,
  email: {
    type: DataTypes.STRING,
    unique: true,
  },
  password: {
    type: DataTypes.STRING,
    allowNull: true, 
  },
  role: {
    type: DataTypes.STRING,
    defaultValue: "user",
  },
});

export default User;
