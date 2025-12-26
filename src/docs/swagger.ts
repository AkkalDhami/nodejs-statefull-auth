import swaggerJSDoc from "swagger-jsdoc";

const swaggerDefinition = {
  openapi: "3.0.0",
  info: {
    title: "Authentication API",
    version: "1.0.0",
    description: "API documentation for the authentication service",
    contact: {
      name: "API Support",
    },
  },
  servers: [
    {
      url: "http://localhost:8000/api/v1",
      description: "Development server",
    },
  ],
  // components: {
  //   securitySchemes: {
  //     bearerAuth: {
  //       type: "http",
  //       scheme: "bearer",
  //       bearerFormat: "JWT",
  //     },
  //   },
  // },
  // security: [
  //   {
  //     bearerAuth: [],
  //   },
  // ],
};

const options = {
  swaggerDefinition,
  apis: ["./src/routes/v1/*.ts", "./src/controllers/*.ts"],
};

export const swaggerSpec = swaggerJSDoc(options);
